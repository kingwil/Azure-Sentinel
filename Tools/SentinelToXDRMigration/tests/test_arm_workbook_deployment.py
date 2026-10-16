"""Synthetic CLI responses test gates, never provider or extension acceptance."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from unittest import mock
import uuid

from sentinel_xdr_migration import arm_workbook_deployment as arm

TENANT = "11111111-2222-3333-4444-555555555555"
SUBSCRIPTION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PRINCIPAL = "12345678-1111-2222-3333-123456789abc"
TARGET = {
    "tenantId": TENANT, "subscriptionId": SUBSCRIPTION,
    "workspaceResourceId": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/lab/providers/"
                           "Microsoft.OperationalInsights/workspaces/workspace",
    "workspaceCustomerId": "99999999-8888-7777-6666-555555555555",
}


class ArmWorkbookDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd() / ("arm-workbook-test-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(self.cleanup_directory)
        self.directory = self.root / "Logs" / "arm-workbook-deployment"
        self.directory.mkdir(parents=True)
        self.cli = self.root / "az.cmd"
        self.cli.write_text("synthetic executable; never launched", encoding="utf-8")
        self.template = {
            "parameters": {
                "workspace": {"type": "string"},
                "location": {"type": "string"}, "workspace-location": {"type": "string"},
                "DeployDefenderWorkbook": {"type": "bool", "defaultValue": False},
                "DeployAnalyticsRule": {"type": "bool", "defaultValue": True},
                "DeployHuntingQuery": {"type": "bool", "defaultValue": True},
                "DeployDataConnector": {"type": "bool", "defaultValue": True},
                "DeployPlaybook": {"type": "bool", "defaultValue": True},
                "DeployWorkbook": {"type": "bool", "defaultValue": True},
            },
            "resources": [
                {"type": "Microsoft.Resources/deployments", "name": "DefenderWorkbook-test",
                 "condition": "[parameters('DeployDefenderWorkbook')]",
                 "properties": {
                     "mode": "Incremental", "expressionEvaluationOptions": {"scope": "inner"},
                     "template": {
                         "imports": {"security": {"provider": "MicrosoftSecurity", "version": "1.0.0"}},
                         "resources": {"workbook": {
                             "type": "Microsoft.Security/workbooks@2026-06-01-preview",
                             "import": "security", "name": "stable-workbook-id", "properties": {},
                         }},
                     },
                 }},
                {"type": "Microsoft.OperationalInsights/workspaces/providers/contentPackages",
                 "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/package')]",
                 "properties": {}},
                {"type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                 "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/registration')]",
                 "properties": {}},
                {"type": "Microsoft.SecurityInsights/alertRules", "name": "excluded",
                 "condition": "[parameters('DeployAnalyticsRule')]", "properties": {"enabled": True}},
            ],
            "variables": {"query": "Table\n| where Message == '  preserve whitespace  '\n"},
        }
        self.provenance = {"mainTemplateSha256": "a" * 64, "zipSha256": "b" * 64,
                           "packageInputIdentity": "c" * 64, "authoredWorkbooks": []}
        inputs = mock.patch.object(arm, "_inputs", side_effect=lambda _: (deepcopy(self.template),
                                                                         deepcopy(self.provenance)))
        directory = mock.patch.object(arm, "_local_directory", return_value=self.directory)
        inputs.start()
        directory.start()
        self.addCleanup(inputs.stop)
        self.addCleanup(directory.stop)
        self.calls = []
        self.states = ["Succeeded"]
        self.claims = {"tid": TENANT, "oid": PRINCIPAL, "aud": arm.ARM + "/",
                       "exp": time.time() + 3600, "scp": "user_impersonation", "idtyp": "user"}
        self.account = {"tenantId": TENANT, "id": SUBSCRIPTION}
        self.workspace = {"id": TARGET["workspaceResourceId"], "location": "eastus",
                          "properties": {"customerId": TARGET["workspaceCustomerId"]}}
        self.validation = {"properties": {"provisioningState": "Succeeded"}}
        self.failed_command = None
        self.before_put = None

    def cleanup_directory(self):
        for attempt in range(20):
            try:
                shutil.rmtree(self.root)
                return
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.1)

    def plan(self):
        return arm.plan_arm_workbook(str(self.root), target=TARGET, location="eastus",
                                     principal_object_id=PRINCIPAL, azure_cli=str(self.cli),
                                     azure_config_dir=str(self.root / "profile"))

    def review(self, plan, approved=True):
        return arm.review_arm_workbook(plan["planPath"], expected_sha256=plan["planSha256"],
                                       actor="explicit user", reference="test approval only", approved=approved)

    def runner(self, command, **kwargs):
        self.calls.append(command)
        tail = command[1:]
        if self.failed_command and self.failed_command in tail:
            return subprocess.CompletedProcess(command, 1, "", "synthetic provider failure")
        if tail[:2] == ["account", "show"]:
            result = self.account
        elif tail[:2] == ["account", "get-access-token"]:
            if "--subscription" in tail and "--tenant" in tail:
                return subprocess.CompletedProcess(
                    command, 1, "", "usage error: specify either --subscription or --tenant, not both")
            payload = base64.urlsafe_b64encode(json.dumps(self.claims).encode()).decode().rstrip("=")
            result = {"accessToken": "header." + payload + ".signature"}
        elif tail[:3] == ["deployment", "group", "validate"]:
            self.assertIn("Provider", tail)
            result = self.validation
            if self.before_put:
                self.before_put()
        elif "put" in tail:
            result = {"properties": {"provisioningState": "Accepted"}}
            body = Path(tail[tail.index("--body") + 1][1:])
            self.assertEqual(arm._hash(body.read_bytes()), self.approved["requestSha256"])
        elif TARGET["workspaceResourceId"] in tail[tail.index("--url") + 1]:
            result = self.workspace
        else:
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            result = {"id": tail[tail.index("--url") + 1].split("?", 1)[0][len(arm.ARM):],
                      "properties": {"provisioningState": state}}
            if state == "Failed":
                result["properties"]["error"] = {"code": "SyntheticFailure", "message": "provider rejected"}
        return subprocess.CompletedProcess(command, 0, json.dumps(result), "")

    def execute(self, plan):
        self.approved = plan
        return arm.execute_arm_workbook(plan["planPath"], expected_sha256=plan["planSha256"],
                                        actor="explicit user", confirmation=arm.CONFIRMATION,
                                        command_runner=self.runner, poll_seconds=0, timeout_seconds=1)

    def assert_no_put(self):
        self.assertFalse(any("put" in command for command in self.calls))

    def test_exact_scope_compaction_and_unconditional_registrations(self):
        plan = self.plan()
        self.assertEqual({k: v for k, v in plan["parameters"].items() if k.startswith("Deploy")},
                         {k: k == "DeployDefenderWorkbook" for k in self.template["parameters"]
                          if k.startswith("Deploy")})
        self.assertEqual(len(plan["resources"]), 4)
        self.assertIn("Microsoft.Security/workbooks", [row["type"] for row in plan["resources"]])
        compact = Path(plan["planPath"]).parent / "template.json"
        self.assertEqual(json.loads(compact.read_bytes()), self.template)
        self.assertEqual(json.loads(compact.read_bytes())["variables"]["query"],
                         self.template["variables"]["query"])
        self.assertEqual(self.calls, [])

    def test_only_polled_succeeded_is_success_not_submission(self):
        plan = self.plan()
        self.review(plan)
        self.states = ["Running", "Succeeded"]
        result = self.execute(plan)
        self.assertEqual(result["status"], "arm-succeeded")
        self.assertTrue(result["deploymentRecordReadback"])
        for field in ("installationVerified", "runtimeVerified", "extensionDirectContractVerified",
                      "qualificationCompleted"):
            self.assertFalse(result[field])
        persisted = json.loads(Path(result["evidencePath"]).read_bytes())
        self.assertEqual(persisted["providerValidation"]["parametersSha256"], plan["parametersSha256"])
        self.assertNotIn("accessToken", json.dumps(persisted))
        with self.assertRaisesRegex(ValueError, "reconcile"):
            self.execute(plan)

    def test_failed_canceled_missing_and_timeout_never_succeed(self):
        for state in ("Failed", "Canceled", None, "Running"):
            with self.subTest(state=state):
                self.template["variables"]["case"] = str(state)
                plan = self.plan()
                self.review(plan)
                self.states = [state]
                result = self.execute(plan)
                self.assertNotEqual(result["status"], "arm-succeeded")
                if state == "Failed":
                    self.assertEqual(result["error"]["code"], "SyntheticFailure")

    def test_token_command_uses_subscription_without_tenant_on_both_checks(self):
        rejected = self.runner([str(self.cli), "account", "get-access-token",
                                "--subscription", SUBSCRIPTION, "--tenant", TENANT])
        self.assertNotEqual(rejected.returncode, 0)
        self.calls.clear()
        plan = self.plan()
        self.review(plan)
        self.assertEqual(self.execute(plan)["status"], "arm-succeeded")
        tokens = [command for command in self.calls if command[1:3] == ["account", "get-access-token"]]
        self.assertEqual(len(tokens), 2)
        for command in tokens:
            self.assertEqual(command[command.index("--subscription") + 1], SUBSCRIPTION)
            self.assertNotIn("--tenant", command)

    def test_wrong_token_tenant_blocks_before_validation_or_reservation(self):
        plan = self.plan()
        self.review(plan)
        self.claims["tid"] = PRINCIPAL
        result = self.execute(plan)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["writeAttempted"])
        self.assertIn("exact approved", result["error"])
        self.assertEqual(Path(result["evidencePath"]).name, "preflight.json")
        self.assertFalse((Path(plan["planPath"]).parent / "attempt.json").exists())
        self.assertFalse(any("validate" in command for command in self.calls))
        self.assert_no_put()
        self.assertFalse(json.loads(Path(result["evidencePath"]).read_bytes())["writeAttempted"])

    def test_token_preflight_failure_allows_same_unchanged_approved_plan(self):
        plan = self.plan()
        self.review(plan)
        directory = Path(plan["planPath"]).parent
        snapshots = {name: (directory / name).read_bytes() for name in
                     ("plan.json", "template.json", "parameters.json", "request.json", "review.json")}
        self.failed_command = "get-access-token"
        result = self.execute(plan)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["writeAttempted"])
        self.assertFalse((directory / "attempt.json").exists())
        self.assert_no_put()
        self.failed_command = None
        self.assertEqual(self.execute(plan)["status"], "arm-succeeded")
        for name, raw in snapshots.items():
            self.assertEqual((directory / name).read_bytes(), raw)
        with self.assertRaisesRegex(ValueError, "reconcile"):
            self.execute(plan)

    def test_provider_validation_failure_and_missing_state_block_put(self):
        for validation in ({"properties": {"provisioningState": "Failed"}},
                           {}, {"properties": {"provisioningState": "Succeeded", "error": {"code": "bad"}}}):
            self.validation = validation
            plan = self.plan()
            self.review(plan)
            self.assertEqual(self.execute(plan)["status"], "blocked")
            self.assert_no_put()

    def test_account_workspace_and_token_mismatches_block_put(self):
        cases = [
            ("account", "tenantId", PRINCIPAL), ("account", "id", PRINCIPAL),
            ("workspace", "location", "westus"),
            ("claims", "tid", PRINCIPAL), ("claims", "oid", TENANT),
            ("claims", "aud", "https://graph.microsoft.com"),
            ("claims", "exp", time.time() - 1), ("claims", "idtyp", "app"),
            ("claims", "scp", "CustomDetection.ReadWrite.All"),
        ]
        for owner, key, value in cases:
            with self.subTest(owner=owner, key=key):
                mapping = getattr(self, owner)
                old = mapping[key]
                mapping[key] = value
                plan = self.plan()
                self.review(plan)
                self.assertEqual(self.execute(plan)["status"], "blocked")
                self.assert_no_put()
                mapping[key] = old

    def test_customer_id_mismatch_blocks_put(self):
        self.workspace["properties"]["customerId"] = PRINCIPAL
        plan = self.plan()
        self.review(plan)
        self.assertEqual(self.execute(plan)["status"], "blocked")
        self.assert_no_put()

    def test_tampered_snapshots_and_source_do_not_dispatch(self):
        for name in ("template.json", "parameters.json", "request.json", "plan.json"):
            with self.subTest(name=name):
                self.template["variables"]["case"] = name
                plan = self.plan()
                self.review(plan)
                path = Path(plan["planPath"]).parent / name
                path.write_bytes(b"{}")
                with self.assertRaises((ValueError, KeyError)):
                    self.execute(plan)
                self.assert_no_put()
        self.template["variables"]["case"] = "source-change"
        plan = self.plan()
        self.review(plan)
        self.provenance["mainTemplateSha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "changed"):
            self.execute(plan)

    def test_confirmation_revocation_and_actor_are_separate_gates(self):
        plan = self.plan()
        self.review(plan, approved=False)
        with self.assertRaisesRegex(ValueError, "review"):
            self.execute(plan)
        self.review(plan)
        for actor, confirmation in (("another user", arm.CONFIRMATION), ("explicit user", "yes")):
            with self.assertRaisesRegex(ValueError, "review"):
                arm.execute_arm_workbook(plan["planPath"], expected_sha256=plan["planSha256"],
                                         actor=actor, confirmation=confirmation, command_runner=self.runner)
        self.assert_no_put()

    def test_post_validation_tamper_and_revocation_block_put(self):
        for change in ("template", "review"):
            self.template["variables"]["case"] = change
            plan = self.plan()
            self.review(plan)
            def tamper():
                if change == "template":
                    (Path(plan["planPath"]).parent / "template.json").write_bytes(b"{}")
                else:
                    self.review(plan, approved=False)
            self.before_put = tamper
            self.assertEqual(self.execute(plan)["status"], "blocked")
            self.assert_no_put()

    def test_cli_failure_after_submission_remains_unknown_and_no_retry(self):
        plan = self.plan()
        self.review(plan)
        self.failed_command = "put"
        result = self.execute(plan)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["writeAttempted"])
        self.assertIn("synthetic provider failure", result["error"])
        with self.assertRaisesRegex(ValueError, "reconcile"):
            self.execute(plan)

    def test_principal_drift_after_validation_and_reservation_race_block_put(self):
        plan = self.plan()
        self.review(plan)
        self.before_put = lambda: self.claims.update(oid=TENANT)
        self.assertEqual(self.execute(plan)["status"], "blocked")
        self.assert_no_put()
        self.claims["oid"] = PRINCIPAL
        attempt = Path(plan["planPath"]).parent / "attempt.json"
        foreign = b'{"status":"another executor reserved this attempt"}'
        self.before_put = lambda: attempt.write_bytes(foreign)
        self.assertEqual(self.execute(plan)["status"], "blocked")
        self.assertEqual(attempt.read_bytes(), foreign)
        self.assert_no_put()

    def test_expired_review_and_wrong_expected_hash_cannot_execute(self):
        plan = self.plan()
        review = self.review(plan)
        review["reviewedAt"] = time.time() - 3601
        review.pop("reviewSha256")
        review["reviewSha256"] = arm._canonical_sha256(review)
        (Path(plan["planPath"]).parent / "review.json").write_bytes(arm._bytes(review))
        with self.assertRaisesRegex(ValueError, "review"):
            self.execute(plan)
        with self.assertRaisesRegex(ValueError, "changed"):
            arm.execute_arm_workbook(plan["planPath"], expected_sha256="0" * 64,
                                     actor="explicit user", confirmation=arm.CONFIRMATION,
                                     command_runner=self.runner)
        self.assert_no_put()

    def test_request_size_includes_envelope_and_reserialization(self):
        baseline = self.plan()["requestSizeBoundBytes"]
        with mock.patch.object(arm, "MAX_REQUEST_BYTES", baseline - 1):
            with self.assertRaisesRegex(ValueError, "4 MiB"):
                self.plan()
        self.template["variables"]["query"] = "\u2603" * (arm.MAX_REQUEST_BYTES // 5)
        with self.assertRaisesRegex(ValueError, "4 MiB"):
            self.plan()

    def test_unsupported_and_cross_tenant_resources_block_planning(self):
        for kind in ("Microsoft.Authorization/roleAssignments", "Microsoft.Logic/workflows",
                     "Microsoft.Security/detectionRules"):
            self.template["resources"].append({"type": kind, "name": "not-approved", "properties": {}})
            with self.assertRaises(ValueError):
                self.plan()
            self.template["resources"].pop()
        nested = self.template["resources"][0]["properties"]["template"]
        nested["imports"]["security"]["config"] = {"tenantId": PRINCIPAL}
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.plan()


if __name__ == "__main__":
    unittest.main()

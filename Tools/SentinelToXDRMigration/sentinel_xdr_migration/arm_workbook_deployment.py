"""Exact-scope normal ARM deployment, not the extension-direct contract executor."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .arm_acceptance_support import _canonical_sha256, _run_cli
from .graph_client_config import azure_cli_profile
from .graph_readiness import _token_claims
from .packaging import _verify_workbook_package, package_input_identity
from .target_context import build_target
from .workbook_publication import digest, publication_errors
from .workbook_validation import _resource_inventory
from .workbooks import selected_workbook_files

CONFIRMATION = "I approve this exact normal ARM workbook deployment and enumerated registrations"
ARM = "https://management.azure.com"
API = "2025-04-01"
MAX_REQUEST_BYTES = 4 * 1024 * 1024
_ALLOWED_TYPES = {
    "microsoft.resources/deployments",
    "microsoft.security/workbooks",
    "microsoft.operationalinsights/workspaces/providers/contenttemplates",
    "microsoft.operationalinsights/workspaces/providers/contentpackages",
    "microsoft.operationalinsights/workspaces/savedsearches",
}


def _bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _properties(response: dict) -> dict:
    properties = response.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("ARM response properties must be an object")
    return properties


def _json(path: Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def _safe(path: Path) -> None:
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("ARM deployment artifacts cannot use symlinks")


def _local_directory(root: Path) -> Path:
    directory = root / "Logs" / "arm-workbook-deployment"
    _safe(directory)
    tracked = subprocess.run(["git", "-C", str(root), "ls-files", "--", str(directory)],
                             capture_output=True, text=True, check=True)
    ignored = subprocess.run(["git", "-C", str(root), "check-ignore", "--quiet",
                              str(directory / "plan.json")], capture_output=True)
    if tracked.stdout.strip() or ignored.returncode:
        raise ValueError("ARM deployment evidence must be untracked and gitignored under solution Logs")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _inputs(root: Path) -> tuple[dict, dict]:
    template_path = root / "Package" / "mainTemplate.json"
    _safe(template_path)
    template = _json(template_path)
    files = selected_workbook_files(root)
    if not files:
        raise ValueError("normal ARM workbook deployment requires selected authored Defender workbooks")
    reviews = []
    for path in files:
        _safe(path)
        document = _json(path)
        errors = publication_errors(root, document)
        if errors:
            raise ValueError(f"{path.name}: {'; '.join(errors)}")
        receipt = root / "Logs" / "workbook-reviews" / (digest(document) + ".json")
        _safe(receipt)
        reviews.append({"path": str(path.relative_to(root)), "sha256": _hash(path.read_bytes()),
                        "authoringReceiptSha256": _hash(receipt.read_bytes())})
    version = template.get("variables", {}).get("_solutionVersion")
    if not isinstance(version, str) or not version or any(c not in "0123456789." for c in version):
        raise ValueError("a resolved V3.1 package version is required")
    zip_path = root / "Package" / (version + ".zip")
    _safe(zip_path)
    _verify_workbook_package(root, files, template, zip_path)
    return template, {
        "mainTemplateSha256": _hash(template_path.read_bytes()),
        "version": version, "zipSha256": _hash(zip_path.read_bytes()),
        "packageInputIdentity": package_input_identity(root)["sha256"],
        "authoredWorkbooks": reviews,
    }


def _scope(root: Path, target: dict, location: str, principal: str,
           azure_cli: str, profile: str) -> tuple[dict, bytes, bytes, bytes]:
    target = build_target(tenant_id=target["tenantId"], subscription_id=target["subscriptionId"],
                          workspace_resource_id=target["workspaceResourceId"],
                          workspace_customer_id=target["workspaceCustomerId"])
    principal = str(uuid.UUID(principal))
    if not location or not location.isalnum():
        raise ValueError("an explicit Azure workspace location is required")
    template, provenance = _inputs(root)
    definitions = template.get("parameters") or {}
    if definitions.get("DeployDefenderWorkbook", {}).get("type") != "bool":
        raise ValueError("template must declare boolean DeployDefenderWorkbook")
    parameters = {"workspace": target["workspaceName"], "workspace-location": location, "location": location}
    for name, definition in definitions.items():
        if name.startswith("Deploy"):
            if definition.get("type") != "bool":
                raise ValueError("all Deploy* flags must be boolean")
            parameters[name] = name == "DeployDefenderWorkbook"
        elif name not in parameters and "defaultValue" not in definition:
            raise ValueError(f"unsupported required template parameter: {name}")
    if not parameters.keys() <= definitions.keys():
        raise ValueError("template must declare workspace, workspace-location and location")
    inventory = _resource_inventory(template, parameters, target)
    if any(row["type"].casefold() not in _ALLOWED_TYPES for row in inventory):
        raise ValueError("workbook-only scope excludes active rules, connectors, playbooks and unknown resources")
    template_raw = _bytes(template)
    params_raw = _bytes({name: {"value": value} for name, value in parameters.items()})
    body = {"properties": {"mode": "Incremental", "template": template,
                           "parameters": json.loads(params_raw)}}
    request = _bytes(body)
    # az rest versions may reserialize parsed JSON using default separators/ASCII.
    # Bound both representations, including the full request envelope.
    request_bound = max(len(request), len(json.dumps(body, allow_nan=False).encode("utf-8")))
    if request_bound > MAX_REQUEST_BYTES:
        raise ValueError(f"normal ARM request exceeds the 4 MiB limit ({request_bound} bytes)")
    plan = {
        "schemaVersion": 1, "route": "normal-arm-resource-group-template",
        "workflowProfile": "qualification", "solution": str(root), "target": target,
        "location": location, "principalObjectId": principal,
        "azureCli": azure_cli, "azureConfigDir": profile,
        **provenance, "templateCompactSha256": _hash(template_raw),
        "parameters": parameters, "parametersSha256": _hash(params_raw),
        "requestSha256": _hash(request), "requestSizeBoundBytes": request_bound,
        "resources": inventory, "deploymentMode": "Incremental",
        "validation": "runtime Provider validation of these exact template and parameter bytes",
        "approvalScope": [
            "existing cached ARM user authentication, target metadata GET and Provider validation",
            "one Incremental whole-template ARM deployment, including every enumerated unconditional registration",
            "poll and read back this ARM deployment record only; no retry after submission",
        ],
        "extensionDirectContractVerified": False, "installationVerified": False,
        "runtimeVerified": False, "qualificationCompleted": False,
        "confirmation": CONFIRMATION,
    }
    plan["planSha256"] = _canonical_sha256(plan)
    plan["deploymentName"] = "workbook-arm-" + plan["planSha256"][:40]
    return plan, template_raw, params_raw, request


def plan_arm_workbook(solution: str, *, target: dict, location: str,
                      principal_object_id: str, azure_cli: str | None = None,
                      azure_config_dir: str | None = None) -> dict:
    root = Path(solution).expanduser().resolve(strict=True)
    executable = azure_cli or shutil.which("az")
    if not executable or not Path(executable).is_file():
        raise ValueError("supply an installed Azure CLI executable using --azure-cli")
    profile = str(Path(azure_config_dir or os.environ.get("AZURE_CONFIG_DIR")
                       or Path.home() / ".azure").expanduser().resolve())
    plan, template, params, request = _scope(root, target, location, principal_object_id,
                                             str(Path(executable).resolve()), profile)
    directory = _local_directory(root) / plan["planSha256"]
    _safe(directory)
    directory.mkdir(exist_ok=True)
    for name, raw in (("plan.json", _bytes(plan)), ("template.json", template),
                      ("parameters.json", params), ("request.json", request)):
        path = directory / name
        _safe(path)
        if path.exists() and path.read_bytes() != raw:
            raise ValueError("an immutable ARM plan artifact changed; reconcile it explicitly")
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(raw)
    return {**plan, "planPath": str(directory / "plan.json"), "status": "planned"}


def _current(path: str, expected_sha256: str) -> tuple[dict, Path]:
    source = Path(path).expanduser().absolute()
    _safe(source)
    plan = _json(source)
    current, template, params, request = _scope(
        Path(plan["solution"]), plan["target"], plan["location"], plan["principalObjectId"],
        plan["azureCli"], plan["azureConfigDir"])
    if plan != current or current["planSha256"] != expected_sha256:
        raise ValueError("ARM template, target, parameters, principal or provenance changed after planning")
    expected_dir = _local_directory(Path(plan["solution"])) / expected_sha256
    if source != expected_dir / "plan.json":
        raise ValueError("plan must remain at its original ignored evidence path")
    for name, raw in (("template.json", template), ("parameters.json", params), ("request.json", request)):
        artifact = source.parent / name
        _safe(artifact)
        if artifact.read_bytes() != raw:
            raise ValueError(f"ARM plan snapshot tampered: {name}")
    return current, source.parent


def review_arm_workbook(path: str, *, expected_sha256: str, actor: str,
                        reference: str, approved: bool) -> dict:
    plan, directory = _current(path, expected_sha256)
    if not actor.strip() or not reference.strip():
        raise ValueError("review requires the user approval actor and reference")
    review = {"planSha256": plan["planSha256"], "actor": actor, "reference": reference,
              "approved": approved, "reviewedAt": time.time()}
    review["reviewSha256"] = _canonical_sha256(review)
    _safe(directory / "review.json")
    (directory / "review.json").write_bytes(_bytes(review))
    return review


def _principal(call, plan: dict) -> None:
    target = plan["target"]
    account = call(["account", "show", "--subscription", target["subscriptionId"]])
    if (str(account.get("id", "")).casefold() != target["subscriptionId"].casefold()
            or str(account.get("tenantId", "")).casefold() != target["tenantId"].casefold()):
        raise ValueError("existing Azure CLI tenant/subscription mismatch; no login or account switch attempted")
    token = call(["account", "get-access-token", "--resource", ARM + "/",
                  "--subscription", target["subscriptionId"], "--tenant", target["tenantId"]])
    claims = _token_claims(token.get("accessToken", "")) or {}
    if (str(claims.get("tid", "")).casefold() != target["tenantId"].casefold()
            or str(claims.get("oid", "")).casefold() != plan["principalObjectId"].casefold()
            or claims.get("aud") not in {ARM, ARM + "/", "https://management.core.windows.net/",
                                         "https://management.core.windows.net"}
            or not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time() + 120
            or claims.get("idtyp") == "app" or "user_impersonation" not in str(claims.get("scp", "")).split()):
        raise ValueError("cached ARM token is not the exact approved, unexpired delegated user principal")


def execute_arm_workbook(path: str, *, expected_sha256: str, actor: str,
                         confirmation: str, command_runner=None,
                         poll_seconds: float = 5, timeout_seconds: float = 1800) -> dict:
    plan, directory = _current(path, expected_sha256)
    review_path = directory / "review.json"
    _safe(review_path)
    review = _json(review_path)
    seal = review.pop("reviewSha256", None)
    if (seal != _canonical_sha256(review) or review.get("planSha256") != expected_sha256
            or review.get("approved") is not True or review.get("actor") != actor
            or not actor.strip() or confirmation != CONFIRMATION
            or not 0 <= time.time() - review.get("reviewedAt", 0) <= 3600):
        raise ValueError("fresh exact-scope user review and immediate write confirmation required")
    if timeout_seconds <= 0 or poll_seconds < 0:
        raise ValueError("poll timeout must be positive and interval nonnegative")
    attempt = directory / "attempt.json"
    _safe(attempt)
    if attempt.exists():
        raise ValueError("an ARM attempt exists; reconcile its authoritative outcome before any retry")
    report = {"planSha256": expected_sha256, "reviewSha256": seal, "actor": actor,
              "target": plan["target"], "deploymentName": plan["deploymentName"],
              "writeAttempted": False, "status": "preflight", "installationVerified": False,
              "extensionDirectContractVerified": False, "runtimeVerified": False,
              "qualificationCompleted": False}

    def call(command, *, allow_empty=False, command_timeout=1800):
        status, result, error = _run_cli([*command, "--output", "json", "--only-show-errors"],
                                         runner=command_runner, azure_cli=plan["azureCli"],
                                         timeout_seconds=command_timeout)
        if status or not isinstance(result, dict) and not (allow_empty and result is None):
            if isinstance(result, dict) and result.get("error"):
                error = (error + " " + json.dumps(result["error"]))[:4000]
            raise RuntimeError(error or f"Azure CLI returned no JSON object for {command[0]}")
        return result or {}

    def persist():
        attempt.write_bytes(_bytes(report))

    target = plan["target"]
    deployment_url = (f"{ARM}/subscriptions/{target['subscriptionId']}/resourceGroups/"
                      f"{quote(target['resourceGroup'], safe='')}/providers/Microsoft.Resources/"
                      f"deployments/{plan['deploymentName']}?api-version={API}")
    reserved = False
    with azure_cli_profile(plan["azureConfigDir"]):
        try:
            _principal(call, plan)
            workspace = call(["rest", "--method", "get", "--url",
                              ARM + target["workspaceResourceId"] + "?api-version=2023-09-01",
                              "--subscription", target["subscriptionId"]])
            if (str(workspace.get("id", "")).casefold() != target["workspaceResourceId"].casefold()
                    or str(_properties(workspace).get("customerId", "")).casefold()
                    != target["workspaceCustomerId"].casefold()
                    or str(workspace.get("location", "")).casefold() != plan["location"].casefold()):
                raise ValueError("live workspace identity/customerId/location mismatch")
            validation = call(["deployment", "group", "validate", "--validation-level", "Provider",
                               "--subscription", target["subscriptionId"], "--resource-group", target["resourceGroup"],
                               "--name", plan["deploymentName"], "--template-file", str(directory / "template.json"),
                               "--parameters", "@" + str(directory / "parameters.json")])
            state = _properties(validation).get("provisioningState")
            if state != "Succeeded" or validation.get("error") or _properties(validation).get("error"):
                raise RuntimeError("Provider validation did not record Succeeded: " + json.dumps(validation)[:4000])
            report["providerValidation"] = {
                "provisioningState": state, "templateSha256": plan["templateCompactSha256"],
                "parametersSha256": plan["parametersSha256"], "validatedAt": time.time(),
            }
            _principal(call, plan)
            _current(path, expected_sha256)
            if _json(review_path).get("reviewSha256") != seal:
                raise ValueError("scope review changed or was revoked before submission")
            # Reserve durably before the only write; any interruption now requires reconciliation.
            with attempt.open("xb") as stream:
                stream.write(_bytes(report))
            reserved = True
            report.update(status="submitting", writeAttempted=True, requestSha256=plan["requestSha256"])
            persist()
            submitted = call(["rest", "--method", "put", "--url", deployment_url,
                              "--subscription", target["subscriptionId"], "--headers", "Content-Type=application/json",
                              "--body", "@" + str(directory / "request.json")],
                             allow_empty=True)
            report["submissionState"] = _properties(submitted).get("provisioningState")
            deadline = time.monotonic() + timeout_seconds
            while True:
                observed = call(["rest", "--method", "get", "--url", deployment_url,
                                 "--subscription", target["subscriptionId"]],
                                command_timeout=max(1, min(90, deadline - time.monotonic())))
                expected_id = deployment_url.split("?", 1)[0][len(ARM):]
                if str(observed.get("id", "")).casefold() != expected_id.casefold():
                    raise RuntimeError("ARM deployment readback identity mismatch")
                props = _properties(observed)
                report.update(provisioningState=props.get("provisioningState"),
                              deploymentId=observed["id"], error=props.get("error") or observed.get("error"),
                              deploymentRecordReadback=True)
                state = report["provisioningState"]
                if state in {"Succeeded", "Failed", "Canceled"}:
                    report["status"] = "arm-succeeded" if state == "Succeeded" and not report["error"] else "failed"
                    break
                if state is None or time.monotonic() >= deadline:
                    report["status"] = "unknown"
                    report["error"] = "missing or nonterminal ARM state; reconcile, do not retry"
                    break
                report["status"] = "polling"
                persist()
                time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))
        except (ValueError, RuntimeError, OSError) as exc:
            report.update(status="unknown" if report["writeAttempted"] else "blocked", error=str(exc))
        if reserved:
            persist()
        else:
            _safe(directory / "preflight.json")
            (directory / "preflight.json").write_bytes(_bytes(report))
    return {**report, "evidencePath": str(attempt if reserved else directory / "preflight.json")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="Offline plan; never authenticates or deploys.")
    plan.add_argument("--solution", required=True)
    plan.add_argument("--workflow-profile", required=True, choices=["qualification"])
    plan.add_argument("--target", required=True, help="Credential-free exact lab target JSON.")
    plan.add_argument("--location", required=True)
    plan.add_argument("--principal-object-id", required=True)
    plan.add_argument("--azure-cli")
    plan.add_argument("--azure-config-dir")
    for command in ("review", "execute"):
        child = commands.add_parser(command)
        child.add_argument("--plan", required=True)
        child.add_argument("--expected-plan-sha256", required=True)
        child.add_argument("--actor", required=True)
        if command == "review":
            child.add_argument("--reference", required=True)
            child.add_argument("--decision", choices=["approve", "revoke"], required=True)
        else:
            child.add_argument("--confirm-exact-scope-write", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = plan_arm_workbook(args.solution, target=_json(Path(args.target)),
                                       location=args.location, principal_object_id=args.principal_object_id,
                                       azure_cli=args.azure_cli, azure_config_dir=args.azure_config_dir)
        elif args.command == "review":
            result = review_arm_workbook(args.plan, expected_sha256=args.expected_plan_sha256,
                                         actor=args.actor, reference=args.reference, approved=args.decision == "approve")
        else:
            result = execute_arm_workbook(args.plan, expected_sha256=args.expected_plan_sha256,
                                          actor=args.actor, confirmation=args.confirm_exact_scope_write)
        print(json.dumps(result, indent=2))
        return 0 if args.command != "execute" or result["status"] == "arm-succeeded" else 1
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

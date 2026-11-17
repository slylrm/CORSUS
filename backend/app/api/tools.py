"""
Tools API Endpoints
Dynamic pentest tool discovery, status, and health checks.
"""

from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Optional

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.tools.registry import (
    canonical_tool_name,
    get_repository_scan_path,
    get_tool_definition,
    is_tool_installed,
    iter_tool_definitions,
    resolve_tool_path,
)
from app.utils.logger import logger
from app.tools.arsenal import inventory as arsenal_inventory, run_tool


router = APIRouter()


class ToolInfo(BaseModel):
    name: str
    category: str
    description: str
    version: str
    installed: bool
    requires_sudo: bool
    path: Optional[str] = None
    service_url: Optional[str] = None


def _tool_info_payload(tool_name: str) -> ToolInfo:
    definition = get_tool_definition(tool_name)
    if not definition:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")

    path = resolve_tool_path(tool_name)
    service_url = getattr(settings, definition.service_url_setting, None) if definition.service_url_setting else None
    return ToolInfo(
        name=definition.name,
        category=definition.category,
        description=definition.description,
        version=definition.version,
        installed=is_tool_installed(definition.name),
        requires_sudo=definition.requires_sudo,
        path=path,
        service_url=service_url,
    )


@router.get("/", response_model=List[ToolInfo])
async def list_tools():
    return [_tool_info_payload(definition.name) for definition in iter_tool_definitions()]


@router.get("/arsenal")
async def list_arsenal():
    """Central inventory including optional tools that are not needed at startup."""
    items = {item["name"]: item for item in arsenal_inventory()}
    # Use the existing registry's richer path/service discovery for integrated tools.
    for definition in iter_tool_definitions():
        key = definition.name
        if key in items:
            item = items[key]
            item["installed"] = is_tool_installed(key)
            item["executable_path"] = resolve_tool_path(key) or item["executable_path"]
        elif definition.path_setting or definition.service_url_setting:
            path = resolve_tool_path(key)
            items[key] = {
                "name": key, "category": definition.category, "version": definition.version,
                "installed": is_tool_installed(key), "executable_path": path,
                "supported_os": ["Windows", "Linux", "macOS"], "cli_arguments": [],
                "default_arguments": [], "output_formats": ["tool-native"],
                "timeout_seconds": 300, "docker_image": None,
                "documentation_url": None, "github_url": None, "optional": True,
                "capabilities": list(definition.capabilities),
            }
    return list(items.values())


@router.post("/arsenal/{tool_name}/run")
async def run_arsenal_tool(tool_name: str, payload: dict[str, Any]):
    """Run only predefined low-impact local-target profiles (no shell command input)."""
    try:
        return await run_tool(tool_name, str(payload.get("target", "")), payload.get("options"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=424, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{tool_name}")
async def get_tool_info(tool_name: str) -> Dict[str, Any]:
    canonical = canonical_tool_name(tool_name)
    definition = get_tool_definition(canonical)
    if not definition:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")

    info = _tool_info_payload(canonical)
    return {
        **info.model_dump(),
        "aliases": list(definition.aliases),
        "capabilities": list(definition.capabilities),
        "options": definition.option_schema,
        "repository_scan_path": get_repository_scan_path() if definition.target_kind == "repo" else None,
        "target_kind": definition.target_kind,
    }


def _test_binary_tool(tool_name: str) -> Dict[str, Any]:
    resolved_path = resolve_tool_path(tool_name)
    if not resolved_path:
        return {
            "tool": tool_name,
            "status": "missing",
            "path": None,
            "detail": "Binary could not be resolved from settings, backend/app/bin, .venv/Scripts, or PATH.",
        }

    try:
        result = subprocess.run(
            [resolved_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        output = stdout or stderr
        return {
            "tool": tool_name,
            "status": "working" if result.returncode == 0 else "degraded",
            "version": output.splitlines()[0] if output else None,
            "path": resolved_path,
            "exit_code": result.returncode,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Tool self-test failed for {}", tool_name, exc_info=True)
        return {
            "tool": tool_name,
            "status": "error",
            "path": resolved_path,
            "detail": str(exc),
        }


def _test_service_tool(tool_name: str) -> Dict[str, Any]:
    definition = get_tool_definition(tool_name)
    if not definition or not definition.service_url_setting:
        raise HTTPException(status_code=404, detail=f"Unknown service tool: {tool_name}")

    service_url = getattr(settings, definition.service_url_setting, None)
    if not service_url:
        return {
            "tool": tool_name,
            "status": "missing",
            "service_url": None,
            "detail": f"{definition.service_url_setting} is not configured.",
        }

    test_url = service_url.rstrip("/")
    params = None
    if tool_name == "owasp_zap":
        test_url = f"{test_url}/JSON/core/view/version/"
        if settings.ZAP_API_KEY:
            params = {"apikey": settings.ZAP_API_KEY}

    try:
        response = requests.get(test_url, params=params, timeout=5, verify=settings.HTTP_VERIFY_TLS)
        response.raise_for_status()
        payload: Dict[str, Any] = {
            "tool": tool_name,
            "status": "working",
            "service_url": service_url,
            "http_status": response.status_code,
        }
        if tool_name == "owasp_zap":
            payload["version"] = response.json().get("version")
        return payload
    except Exception as exc:  # noqa: BLE001
        return {
            "tool": tool_name,
            "status": "unreachable",
            "service_url": service_url,
            "detail": str(exc),
        }


@router.post("/{tool_name}/test")
async def test_tool(tool_name: str):
    canonical = canonical_tool_name(tool_name)
    definition = get_tool_definition(canonical)
    if not definition:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")

    logger.info(f"Testing tool: {canonical}")

    if definition.path_setting:
        return _test_binary_tool(canonical)
    if definition.service_url_setting:
        return _test_service_tool(canonical)

    return {
        "tool": canonical,
        "status": "unsupported",
        "detail": "No test strategy is defined for this tool.",
    }

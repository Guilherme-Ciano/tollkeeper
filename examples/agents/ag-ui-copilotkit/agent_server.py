import json
import os
import re
import time
import uuid
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import StreamingResponse

TOLLKEEPER_URL = os.environ.get("TOLLKEEPER_URL", "http://localhost:8080/mcp")
AUTH_PARAM_RE = re.compile(r'([a-zA-Z0-9_]+)="([^"]*)"')

app = FastAPI(title="AG-UI + tollkeeper MCP Bridge")


def sse_event(payload: dict[str, Any]) -> str:
    payload.setdefault("timestamp", int(time.time() * 1000))
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"


def parse_www_authenticate(header_value: str) -> dict[str, str]:
    return {match.group(1): match.group(2) for match in AUTH_PARAM_RE.finditer(header_value)}


async def call_tollkeeper_tool(
    tool: str,
    arguments: dict[str, Any],
    authorization: str | None,
    approval_token: str | None = None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
    }
    if authorization:
        headers["Authorization"] = authorization
    if approval_token:
        headers["X-Tollkeeper-Approval"] = approval_token
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    rpc_body = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments,
        },
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(TOLLKEEPER_URL, headers=headers, json=rpc_body)
        challenge = parse_www_authenticate(resp.headers.get("www-authenticate", ""))
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text}
        return resp.status_code, challenge, body


async def stream_ag_ui_run(
    thread_id: str,
    run_id: str,
    tool: str,
    arguments: dict[str, Any],
    authorization: str | None,
    approval_token: str | None = None,
    idempotency_key: str | None = None,
) -> AsyncIterator[str]:
    tool_call_id = f"tc_{uuid.uuid4().hex[:12]}"
    message_id = f"msg_{uuid.uuid4().hex[:12]}"

    yield sse_event({"type": "RUN_STARTED", "threadId": thread_id, "runId": run_id})
    yield sse_event(
        {
            "type": "TOOL_CALL_START",
            "toolCallId": tool_call_id,
            "toolCallName": tool,
        }
    )
    yield sse_event(
        {
            "type": "TOOL_CALL_ARGS",
            "toolCallId": tool_call_id,
            "delta": json.dumps(arguments),
        }
    )
    yield sse_event({"type": "TOOL_CALL_END", "toolCallId": tool_call_id})

    status, challenge, body = await call_tollkeeper_tool(
        tool, arguments, authorization, approval_token, idempotency_key
    )

    rpc_error = body.get("error") if isinstance(body, dict) else None
    if status == 403 and isinstance(rpc_error, dict) and rpc_error.get("code") == -32010:
        data = rpc_error.get("data") or {}
        yield sse_event(
            {
                "type": "CUSTOM",
                "name": "tollkeeper.approval_required",
                "value": {
                    "tool": data.get("tool", tool),
                    "argsHash": data.get("args_hash", ""),
                    "subject": data.get("subject", ""),
                    "tenant": data.get("tenant", ""),
                    "header": data.get("header", "X-Tollkeeper-Approval"),
                    "ttlSeconds": data.get("ttl_s", 300),
                    "reason": data.get("reason", "Explicit human approval required"),
                    "arguments": arguments,
                },
            }
        )
        yield sse_event({"type": "TEXT_MESSAGE_START", "messageId": message_id, "role": "assistant"})
        yield sse_event(
            {
                "type": "TEXT_MESSAGE_CONTENT",
                "messageId": message_id,
                "delta": (
                    f"Tollkeeper requires explicit human approval ({data.get('reason', 'tk-approval+jwt')}) "
                    f"for {tool} (args_hash={data.get('args_hash', '')}). Approve and retry with X-Tollkeeper-Approval."
                ),
            }
        )
        yield sse_event({"type": "TEXT_MESSAGE_END", "messageId": message_id})
        yield sse_event({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})
        return

    if status in (401, 403) and challenge.get("error") in (
        "insufficient_user_authentication",
        "insufficient_scope",
    ):
        yield sse_event(
            {
                "type": "CUSTOM",
                "name": "tollkeeper.step_up_required",
                "value": {
                    "tool": tool,
                    "httpStatus": status,
                    "error": challenge.get("error", ""),
                    "errorDescription": challenge.get("error_description", ""),
                    "acrValues": challenge.get("acr_values", ""),
                    "maxAge": challenge.get("max_age", ""),
                    "scope": challenge.get("scope", ""),
                    "resourceMetadata": challenge.get("resource_metadata", ""),
                },
            }
        )
        yield sse_event({"type": "TEXT_MESSAGE_START", "messageId": message_id, "role": "assistant"})
        yield sse_event(
            {
                "type": "TEXT_MESSAGE_CONTENT",
                "messageId": message_id,
                "delta": (
                    f"Tollkeeper requires step-up authentication ({challenge.get('error')}) "
                    f"before running {tool}. Complete authentication and retry."
                ),
            }
        )
        yield sse_event({"type": "TEXT_MESSAGE_END", "messageId": message_id})
        yield sse_event({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})
        return

    yield sse_event(
        {
            "type": "TOOL_CALL_RESULT",
            "messageId": f"tr_{uuid.uuid4().hex[:12]}",
            "toolCallId": tool_call_id,
            "content": json.dumps(body),
            "role": "tool",
        }
    )
    yield sse_event({"type": "TEXT_MESSAGE_START", "messageId": message_id, "role": "assistant"})
    yield sse_event(
        {
            "type": "TEXT_MESSAGE_CONTENT",
            "messageId": message_id,
            "delta": f"Tool {tool} completed with HTTP {status}.",
        }
    )
    yield sse_event({"type": "TEXT_MESSAGE_END", "messageId": message_id})
    yield sse_event({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})


@app.post("/ag-ui/run")
async def ag_ui_run(
    request: Request,
    authorization: str | None = Header(default=None),
    x_tollkeeper_approval: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None),
) -> StreamingResponse:
    payload = await request.json()
    thread_id = str(payload.get("threadId") or f"thread_{uuid.uuid4().hex[:8]}")
    run_id = str(payload.get("runId") or f"run_{uuid.uuid4().hex[:8]}")
    tool = str(payload.get("tool") or "notes__search")
    arguments = payload.get("arguments") or {}
    return StreamingResponse(
        stream_ag_ui_run(
            thread_id, run_id, tool, arguments, authorization, x_tollkeeper_approval, idempotency_key
        ),
        media_type="text/event-stream",
    )

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from typing import Any, Optional, Union


class SessionRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: dict[str, tuple[str, int]] = {}

    def set(self, name: str, host: str, port: int) -> None:
        with self._lock:
            self._sessions[name] = (host, port)

    def remove(self, name: str) -> None:
        with self._lock:
            self._sessions.pop(name, None)

    def list(self) -> dict[str, dict[str, str]]:
        with self._lock:
            return {k: {"host": v[0], "port": v[1]} for k, v in self._sessions.items()}

    def get(self, name: str) -> tuple[str, int] | None:
        with self._lock:
            return self._sessions.get(name)


registry = SessionRegistry()


class ControlAPI(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/sessions":
            self._send(200, {"sessions": registry.list()})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send(400, {"error": "invalid json"})
            return

        if self.path == "/register":
            name = body.get("name")
            host = body.get("host") or "127.0.0.1"
            port = body.get("port")
            if not name or not isinstance(port, int):
                self._send(400, {"error": "name (str) and port (int) required"})
                return
            registry.set(name, host, port)
            self._send(200, {"ok": True})
            return

        if self.path == "/unregister":
            name = body.get("name")
            if not name:
                self._send(400, {"error": "name required"})
                return
            registry.remove(name)
            self._send(200, {"ok": True})
            return

        self._send(404, {"error": "not found"})


mcp = FastMCP("ida-mmcp")


def _jsonrpc(host: str, port: int, method: str, params: list | dict):
    import http.client

    conn = http.client.HTTPConnection(host, port)
    try:
        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        conn.request("POST", "/mcp", json.dumps(req), {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        if "error" in data:
            err = data["error"]
            raise RuntimeError(f"{err.get('code')}: {err.get('message')}")
        return data.get("result")
    finally:
        conn.close()


@mcp.tool()
def list_sessions() -> dict:
    """List registered IDA sessions keyed by name with host/port."""
    return registry.list()


@mcp.tool()
def select_session(name: str) -> str:
    """Select a default session for subsequent tool calls."""
    if registry.get(name) is None:
        raise RuntimeError(f"unknown session: {name}")
    os.environ["IDA_MMCP_SELECTED"] = name
    return name


def _resolve(name: str | None) -> tuple[str, int]:
    if not name:
        name = os.environ.get("IDA_MMCP_SELECTED")
    if not name:
        raise RuntimeError("no session selected; call select_session(name) first")
    session = registry.get(name)
    if not session:
        raise RuntimeError(f"unknown session: {name}")
    return session


def _proxy_tool(tool_name: str, *args, session: str | None = None, **kwargs):
    host, port = _resolve(session)
    params = list(args) if args else kwargs or []
    result = _jsonrpc(host, port, tool_name, params)
    return result if result is not None else "success"


@mcp.tool()
def list_sessions_metadata() -> list:
    """List metadata for all registered sessions (module, path, base)."""
    out = []
    for name, info in registry.list().items():
        try:
            meta = _jsonrpc(info["host"], info["port"], "get_metadata", [])
        except Exception as e:
            meta = {"error": str(e)}
        out.append({"session": name, "metadata": meta})
    return out


@mcp.tool()
def select_session_by_module(query: str) -> str:
    """Select session by matching query against metadata.module or metadata.path (case-insensitive substring)."""
    q = query.lower()
    for name, info in registry.list().items():
        try:
            meta = _jsonrpc(info["host"], info["port"], "get_metadata", [])
        except Exception:
            continue
        module = str(meta.get("module", "")).lower()
        path = str(meta.get("path", "")).lower()
        if q in module or q in path:
            os.environ["IDA_MMCP_SELECTED"] = name
            return name
    raise RuntimeError(f"no session matched: {query}")


@mcp.tool()
def get_function_by_name_across(name: str) -> list:
    """Search all sessions for a function by name; returns list of {session, function}."""
    results = []
    for sess, info in registry.list().items():
        try:
            fn = _jsonrpc(info["host"], info["port"], "get_function_by_name", [name])
            if fn:
                results.append({"session": sess, "function": fn})
        except Exception:
            continue
    return results


# @mcp.tool()
def proxy_call(
    tool: str,
    params: Optional[Union[list, dict]] = None,
    session: Optional[str] = os.environ.get("IDA_MMCP_SELECTED"),
) -> Any:
    """Call any IDA MCP tool on a selected session. Params may be a list or an object."""
    host, port = _resolve(session)
    return _jsonrpc(host, port, tool, params or [])

def add_proxy_tool(tool_name: str):
    def tool_fn(**kwargs):
        session = kwargs.pop("session", None)
        return _proxy_tool(tool_name, session=session, **kwargs)

    tool_fn.__name__ = tool_name
    tool_fn.__doc__ = f"Proxy to '{tool_name}' on the selected IDA session. Optional 'session' overrides the selection."
    mcp.add_tool(tool_fn, tool_name)

def _try_generate_wrappers_from_ida_pro_mcp() -> bool:
    """Import ida_pro_mcp.server_generated and wrap its tools as aggregator tools.
    Returns True on success, False to allow fallback registration.
    """
    path = os.path.join(os.path.dirname(__file__), "server_generated.py")
    if not os.path.exists(path):
        return False
    
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    exec(compile(src, path, "exec"), globals(), globals())
    print(f"Loaded {path}")
    return True


def load_tools_from_plugin(host: str, port: int):
    if _try_generate_wrappers_from_ida_pro_mcp():
        return

    # Fallback to a minimal static set if import fails
    for name in [
        "get_metadata",
        "get_function_by_name",
        "get_function_by_address",
        "get_current_address",
        "get_current_function",
        "convert_number",
        "list_functions",
        "list_globals_filter",
        "list_globals",
        "list_strings_filter",
        "list_strings",
        "list_local_types",
        "decompile_function",
        "disassemble_function",
        "get_xrefs_to",
        "get_xrefs_to_field",
        "get_entry_points",
        "set_comment",
        "rename_local_variable",
        "rename_global_variable",
        "set_global_variable_type",
        "set_function_prototype",
        "declare_c_type",
        "set_local_variable_type",
        "get_stack_frame_variables",
        "get_defined_structures",
        "rename_stack_frame_variable",
        "create_stack_frame_variable",
        "set_stack_frame_variable_type",
        "delete_stack_frame_variable",
        "read_memory_bytes",
        "data_read_byte",
        "data_read_word",
        "data_read_dword",
        "data_read_qword",
        "data_read_string",
    ]:
        add_proxy_tool(name)


def start_control_api(host: str, port: int):
    server = HTTPServer((host, port), ControlAPI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    parser = argparse.ArgumentParser(description="IDA Multi-MCP aggregator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8746)
    parser.add_argument("--control-host", default="127.0.0.1")
    parser.add_argument("--control-port", type=int, default=8760)
    parser.add_argument("--log-level", default="ERROR")
    args = parser.parse_args()

    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.settings.log_level = args.log_level

    start_control_api(args.control_host, args.control_port)

    # Add proxy tools late-bound; they require a selected session.
    # Preload with a dummy to expose signatures.
    load_tools_from_plugin("127.0.0.1", 13337)

    try:
        print(f"MMCP SSE at http://{args.host}:{args.port}/sse; control at http://{args.control_host}:{args.control_port}")
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()



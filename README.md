# IDA MMCP

Multi-binary MCP aggregator for IDA Pro.

- SSE MCP: http://127.0.0.1:8746/sse
- Control API: http://127.0.0.1:8760
  - POST /register {"name":"projA","host":"127.0.0.1","port":13337}
  - POST /unregister {"name":"projA"}
  - GET /sessions

## Usage

```sh
uv run ida-mmcp --host 127.0.0.1 --port 8746 --control-port 8760
```

IDA plugin UI registers/unregisters itself to the control API and allows selecting the active session.

## Patch
### ida-pro-mcp
- git clone [https://github.com/Kur0N3k0/ida-pro-mcp](https://github.com/Kur0N3k0/ida-pro-mcp)
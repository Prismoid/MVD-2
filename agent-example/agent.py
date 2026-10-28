import asyncio, base64, hashlib, json, urllib.request
from datetime import datetime, timedelta, timezone

import httpx
from ecdsa import SigningKey
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

OLLAMA_URL = "http://gpu.wg.internal:11434/api/chat"
MODEL = "qwen3.8:27b" # "qwen3:14b"
CONNECTOR_MCP = "http://localhost:7550/invoke_resource"
RESOURCE_ID = "mcp-server"
USER_ID = "user"


PRIVATE_KEY = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqYxhjDxzVZv0AFFMAfvHC8iKpXmbckDATOMZuz/9K1oAoGCCqGSM49
AwEHoUQDQgAEz86DFhgDHZoLF/i4EZI9usUZR257wVqeoEsm9YIafEBeNQ0r5zxF
WpCJLab/1JIEsTpz+1Ml1oY3iqwkJ1IAwQ==
-----END EC PRIVATE KEY-----
"""

SK = SigningKey.from_pem(PRIVATE_KEY)


def auth_headers():
    expire = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    data = {"resource_id": RESOURCE_ID, "user_id": USER_ID, "expire_time": expire}
    sig = SK.sign(json.dumps(data, sort_keys=True).encode(), hashfunc=hashlib.sha256)
    return {
        "X-Resource-Id": RESOURCE_ID,
        "X-User-Id": USER_ID,
        "X-Expire-Time": expire,
        "X-Signature": base64.b64encode(sig).decode(),
    }


class ConnectorAuth(httpx.Auth):
    def auth_flow(self, request):
        print("auth activated")
        request.headers.update(auth_headers())  # fresh signature for every HTTP request
        yield request


def chat(messages, tools):
    body = {"model": MODEL, "messages": messages, "tools": tools, "stream": False,
            "think": False, "options": {"temperature": 0, "seed": 42}}
    req = urllib.request.Request(OLLAMA_URL, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["message"]


async def main():
    transport = StreamableHttpTransport(CONNECTOR_MCP, auth=ConnectorAuth())
    async with Client(transport) as client:
        tools = [{"type": "function", "function": {
            "name": t.name, "description": t.description, "parameters": t.inputSchema
        }} for t in await client.list_tools()]

        messages = [
            {"role": "system", "content": "Use MCP tools until the task is complete."},
            {"role": "user", "content": "Check A-1 through A-5, turn on every light that is off, then report the result."},
        ]

        for _ in range(10):
            action = chat(messages, tools)
            messages.append(action)
            calls = action.get("tool_calls") or []
            print(calls)
            if not calls:
                print(action["content"])
                return
            for item in calls:
                call = item["function"]
                result = await client.call_tool(call["name"], call["arguments"])
                print(call, "->", result.data)
                messages.append({"role": "tool", "tool_name": call["name"],
                                 "content": json.dumps(result.data, default=str)})


asyncio.run(main())

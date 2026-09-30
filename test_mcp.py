import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# ============================================================
# MCP SERVER CONFIGURATION
# ============================================================

server_params = StdioServerParameters(
    command=sys.executable,
    args=["mcp_server.py"]
)


# ============================================================
# TEST HELPERS
# ============================================================

passed = 0
failed = 0


def test(name, condition):

    global passed, failed

    if condition:
        print(f"✓ PASS: {name}")
        passed += 1
    else:
        print(f"✗ FAIL: {name}")
        failed += 1


# ============================================================
# MCP TESTS
# ============================================================

async def main():

    global passed, failed

    print()
    print("=" * 60)
    print("Local OS Copilot — MCP Integration Tests")
    print("=" * 60)
    print()

    # --------------------------------------------------------
    # Start actual MCP server
    # --------------------------------------------------------

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            # ------------------------------------------------
            # Initialize MCP connection
            # ------------------------------------------------

            await session.initialize()

            print("MCP connection established.")
            print()

            # ------------------------------------------------
            # TEST 1 — MCP SERVER CONNECTION
            # ------------------------------------------------

            test(
                "MCP server initializes successfully",
                True
            )

            # ------------------------------------------------
            # TEST 2 — LIST TOOLS
            # ------------------------------------------------

            tools_result = await session.list_tools()

            tool_names = {
                tool.name
                for tool in tools_result.tools
            }

            expected_tools = {
                "get_system_metrics",
                "find_process_by_port",
                "inspect_process",
                "find_high_consumption_processes",
                "read_recent_logs",
                "discover_logs"
            }

            test(
                "All expected MCP tools are registered",
                expected_tools.issubset(tool_names)
            )

            print()
            print("Available tools:")

            for name in sorted(tool_names):
                print(f"  - {name}")

            print()

            # ------------------------------------------------
            # TEST 3 — DISCOVER LOGS
            # ------------------------------------------------

            result = await session.call_tool(
                "discover_logs",
                {}
            )

            output = ""

            for content in result.content:

                if hasattr(content, "text"):
                    output += content.text

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}

            logs = data.get("logs", [])

            log_names = {
                log.get("name")
                for log in logs
            }

            test(
                "discover_logs returns available test logs",
                "test_app.log" in log_names
            )

            # ------------------------------------------------
            # TEST 4 — READ NORMAL LOG
            # ------------------------------------------------

            result = await session.call_tool(
                "read_recent_logs",
                {
                    "path": "test_app.log",
                    "lines": 50
                }
            )

            output = ""

            for content in result.content:

                if hasattr(content, "text"):
                    output += content.text

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}

            content = data.get("content", "")

            test(
                "read_recent_logs reads test_app.log",
                "Address already in use" in content
            )

            # ------------------------------------------------
            # TEST 5 — LOG SANITIZATION / SUSPICIOUS CONTENT
            # ------------------------------------------------

            result = await session.call_tool(
                "read_recent_logs",
                {
                    "path": "malicious_test.log",
                    "lines": 50
                }
            )

            output = ""

            for content_item in result.content:

                if hasattr(content_item, "text"):
                    output += content_item.text

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}

            suspicious_lines = data.get(
                "suspicious_instruction_lines",
                []
            )

            test(
                "malicious log instructions are detected",
                len(suspicious_lines) >= 1
            )

            # ------------------------------------------------
            # TEST 6 — PORT INSPECTION
            # ------------------------------------------------

            result = await session.call_tool(
                "find_process_by_port",
                {
                    "port": 8080
                }
            )

            output = ""

            for content in result.content:

                if hasattr(content, "text"):
                    output += content.text

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}

            test(
                "find_process_by_port returns structured data",
                data.get("port") == 8080
                and "processes" in data
            )

            # ------------------------------------------------
            # TEST 7 — SYSTEM METRICS
            # ------------------------------------------------

            result = await session.call_tool(
                "get_system_metrics",
                {}
            )

            output = ""

            for content in result.content:

                if hasattr(content, "text"):
                    output += content.text

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}

            test(
                "get_system_metrics returns CPU/RAM/disk metrics",
                all(
                    key in data
                    for key in [
                        "cpu_percent",
                        "memory_percent",
                        "disk_percent"
                    ]
                )
            )

            # ------------------------------------------------
            # RESULTS
            # ------------------------------------------------

            print()
            print("=" * 60)
            print(
                f"Results: {passed} passed, {failed} failed"
            )
            print("=" * 60)

            if failed > 0:
                raise SystemExit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())
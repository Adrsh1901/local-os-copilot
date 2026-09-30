import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


server_params = StdioServerParameters(
    command=sys.executable,
    args=["mcp_server.py"]
)


async def main():

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            # Initialize MCP connection
            await session.initialize()

            # Discover available tools
            tools = await session.list_tools()

            print("Available tools:")

            for tool in tools.tools:
                print(f"- {tool.name}: {tool.description}")

            # Call system metrics tool
            result = await session.call_tool(
                "get_system_metrics",
                {}
            )

            print("\nSystem metrics:")
            print(result)

            # Call port inspection tool
            result = await session.call_tool(
                "find_process_by_port",
                {"port": 8080}
            )

            print("\nPort 8080:")
            print(result)


if __name__ == "__main__":
    asyncio.run(main())
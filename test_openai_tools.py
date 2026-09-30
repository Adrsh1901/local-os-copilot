from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "find_process_by_port",
            "description": "Find the process using a specific network port.",
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "The network port to inspect."
                    }
                },
                "required": ["port"]
            }
        }
    }
]

response = client.chat.completions.create(
    model="qwen2.5:3b",
    messages=[
        {
            "role": "system",
            "content": "Use the available tool when the user asks about a port."
        },
        {
            "role": "user",
            "content": "What is using port 8080?"
        }
    ],
    tools=tools
)

message = response.choices[0].message

print("CONTENT:")
print(message.content)

print("\nTOOL CALLS:")
print(message.tool_calls)
from ollama import chat

response = chat(
    model="qwen2.5:3b",
    messages=[
        {
            "role": "user",
            "content": "Explain what an MCP server is in simple terms."
        }
    ]
)

print(response.message.content)
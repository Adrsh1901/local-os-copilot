from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

response = client.chat.completions.create(
    model="qwen2.5:3b",
    messages=[
        {"role": "user", "content": "Explain what an MCP server is in one sentence."}
    ]
)

print(response.choices[0].message.content)
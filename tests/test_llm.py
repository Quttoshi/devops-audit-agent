from __future__ import annotations

from auditor.llm import DEFAULT_BASE_URL, LLMResponse, OpenAIChatClient, ToolCall


def test_blank_base_url_env_falls_back_to_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "")  # as left by a blank line in .env
    client = OpenAIChatClient(model="m", api_key="k", base_url=None)
    assert str(client._client.base_url).rstrip("/") == DEFAULT_BASE_URL


def test_custom_base_url_is_used():
    client = OpenAIChatClient(model="m", api_key="k", base_url="http://localhost:11434/v1")
    assert str(client._client.base_url).startswith("http://localhost:11434/v1")


def test_response_to_message_round_trip():
    msg = LLMResponse(content=None, tool_calls=[ToolCall("id1", "list_files", "{}")]).to_message()
    assert msg == {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": "id1", "type": "function", "function": {"name": "list_files", "arguments": "{}"}}],
    }

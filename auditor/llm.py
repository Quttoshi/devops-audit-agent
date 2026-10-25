"""Thin wrapper around the OpenAI Chat Completions API (function calling).

The agent loop depends only on :class:`ChatClient` / :class:`LLMResponse`, so tests can substitute a scripted
fake without network access.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class LLMError(Exception):
    """The LLM provider failed in a way the agent cannot recover from."""


class ContextLengthError(LLMError):
    """The conversation no longer fits into the model's context window."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON string as produced by the model


@dataclass
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)

    def to_message(self) -> dict[str, Any]:
        """The assistant message to append to the conversation history."""
        msg: dict[str, Any] = {"role": "assistant", "content": self.content or ""}
        if self.tool_calls:
            msg["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
                for c in self.tool_calls
            ]
        return msg


class ChatClient(Protocol):
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse: ...


class OpenAIChatClient:
    """OpenAI (or OpenAI-compatible, via ``base_url``) chat client with retries and error mapping."""

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str | None = None,
        timeout: float = 120.0,
        max_retries: int = 4,
        temperature: float | None = None,
    ):
        import openai  # imported lazily so the rest of the package (and tests) work without it configured

        self._openai = openai
        self.model = model
        self.temperature = temperature
        # Always pass an explicit URL: with base_url=None the SDK falls back to $OPENAI_BASE_URL, which may be
        # set but empty (a blank line copied from .env.example) and would break every request.
        self._client = openai.OpenAI(
            api_key=api_key, base_url=base_url or DEFAULT_BASE_URL, timeout=timeout, max_retries=max_retries
        )
        self.total_usage: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0}

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        oa = self._openai
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except oa.AuthenticationError as exc:
            raise LLMError("OpenAI authentication failed: check OPENAI_API_KEY") from exc
        except oa.PermissionDeniedError as exc:
            raise LLMError(f"OpenAI permission denied for model {self.model!r}") from exc
        except oa.NotFoundError as exc:
            raise LLMError(f"model {self.model!r} not found at the configured endpoint (set OPENAI_MODEL)") from exc
        except oa.BadRequestError as exc:
            text = str(exc).lower()
            if "context" in text and ("length" in text or "window" in text) or "too many tokens" in text:
                raise ContextLengthError(str(exc)) from exc
            raise LLMError(f"OpenAI rejected the request: {exc}") from exc
        except oa.RateLimitError as exc:
            raise LLMError("OpenAI rate limit / quota exceeded after retries") from exc
        except (oa.APITimeoutError, oa.APIConnectionError) as exc:
            raise LLMError(f"could not reach the OpenAI API after retries: {exc}") from exc
        except oa.APIError as exc:
            raise LLMError(f"OpenAI API error: {exc}") from exc

        if not resp.choices:
            raise LLMError("OpenAI returned no choices")
        msg = resp.choices[0].message
        calls = [
            ToolCall(id=c.id, name=c.function.name, arguments=c.function.arguments or "{}")
            for c in (msg.tool_calls or [])
            if getattr(c, "function", None) is not None
        ]
        usage = {}
        if resp.usage:
            usage = {
                "prompt_tokens": resp.usage.prompt_tokens or 0,
                "completion_tokens": resp.usage.completion_tokens or 0,
            }
            for k, v in usage.items():
                self.total_usage[k] += v
        return LLMResponse(content=msg.content, tool_calls=calls, usage=usage)

"""A thin provider interface so the free-tier LLM can be swapped."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import openai


class LLMUnavailable(RuntimeError):
    """The provider could not answer: rate limit, outage, bad key or rejected request."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict | None  # None when the model's JSON did not parse
    raw_arguments: str = ""


@dataclass
class Turn:
    content: str | None
    tool_calls: list[ToolCall]
    input_tokens: int = 0
    output_tokens: int = 0
    message: dict = field(default_factory=dict)  # assistant message to append to the conversation


class OpenAICompatLLM:
    """Any provider with an OpenAI-compatible chat completions endpoint."""

    def __init__(self, base_url: str, api_key: str, model: str):
        self.model = model
        self.client = openai.OpenAI(base_url=base_url, api_key=api_key, max_retries=2, timeout=60)

    def chat(self, messages: list[dict], tools: list[dict], tool_choice="auto") -> Turn:
        try:
            response = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=tools, tool_choice=tool_choice, temperature=0)
        except openai.OpenAIError as exc:
            raise LLMUnavailable(str(exc)) from exc
        message = response.choices[0].message
        calls = []
        for call in message.tool_calls or []:
            raw = call.function.arguments or "{}"
            try:
                arguments = json.loads(raw)
            except json.JSONDecodeError:
                arguments = None
            if not isinstance(arguments, dict):
                arguments = None
            calls.append(ToolCall(call.id, call.function.name, arguments, raw))
        usage = response.usage
        return Turn(
            content=message.content,
            tool_calls=calls,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            # Dumped whole so provider-specific fields on tool calls survive the round trip.
            message=message.model_dump(exclude_none=True),
        )


def llm_from_env(env=os.environ) -> OpenAICompatLLM | None:
    base_url, api_key, model = env.get("LLM_BASE_URL"), env.get("LLM_API_KEY"), env.get("LLM_MODEL")
    if not (base_url and api_key and model):
        return None
    return OpenAICompatLLM(base_url, api_key, model)

"""Check that the configured provider supports what the agent needs."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.llm import LLMUnavailable, llm_from_env

WEATHER = {"type": "function", "function": {
    "name": "get_weather", "description": "Get the weather for a city.",
    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}
ANSWER = {"type": "function", "function": {
    "name": "submit_answer", "description": "Submit the final answer.",
    "parameters": {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}}}


def main() -> int:
    llm = llm_from_env()
    if llm is None:
        print("Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL first.")
        return 1
    messages = [{"role": "user", "content": "What is the weather in Paris? Use the tool, then submit the answer."}]
    try:
        first = llm.chat(messages, [WEATHER, ANSWER])
        ok = bool(first.tool_calls) and first.tool_calls[0].name == "get_weather"
        print("1. calls a tool when asked:", "PASS" if ok else "FAIL")
        if not ok:
            return 1
        messages.append(first.message)
        for call in first.tool_calls:
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps({"weather": "sunny, 21C"})})
        forced = {"type": "function", "function": {"name": "submit_answer"}}
        second = llm.chat(messages, [WEATHER, ANSWER], tool_choice=forced)
        ok = bool(second.tool_calls) and second.tool_calls[0].name == "submit_answer" \
            and isinstance(second.tool_calls[0].arguments, dict)
        print("2. accepts tool results and a forced tool choice:", "PASS" if ok else "FAIL")
        print(f"   tokens: {first.input_tokens + second.input_tokens} in, {first.output_tokens + second.output_tokens} out")
        return 0 if ok else 1
    except LLMUnavailable as exc:
        print("FAIL: provider error:", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

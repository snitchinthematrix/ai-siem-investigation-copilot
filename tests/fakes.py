"""A scripted stand-in for the LLM so agent tests run offline."""
from copilot.llm import ToolCall, Turn


def turn(*calls, content=None) -> Turn:
    """turn(("search_events", {"host": "x"})) is one assistant turn making that call."""
    tool_calls = [ToolCall(id=f"call{i}", name=name, arguments=arguments)
                  for i, (name, arguments) in enumerate(calls)]
    return Turn(content=content, tool_calls=tool_calls, input_tokens=10, output_tokens=5,
                message={"role": "assistant", "content": content or ""})


def verdict_args(**overrides) -> dict:
    args = {
        "verdict": "true_positive", "confidence": 0.9, "severity": "high",
        "techniques": ["T1053.005"],
        "timeline": [{"ts": "2020-11-02 15:00:45", "description": "task created", "event_ids": ["E000016"]}],
        "evidence": [{"claim": "schtasks created a hidden PowerShell task", "event_ids": ["E000016"]}],
        "next_actions": ["Isolate workstation8"], "report_md": "## Summary\nMalicious scheduled task.",
    }
    args.update(overrides)
    return args


class FakeLLM:
    """Plays turns in order; the last one repeats. An exception in the list is raised."""

    model = "fake-model"

    def __init__(self, turns):
        self.turns = list(turns)
        self.calls = []

    def chat(self, messages, tools, tool_choice="auto"):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools, "tool_choice": tool_choice})
        item = self.turns.pop(0) if len(self.turns) > 1 else self.turns[0]
        if isinstance(item, Exception):
            raise item
        return item

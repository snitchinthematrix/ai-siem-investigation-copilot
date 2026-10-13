from copilot.llm import OpenAICompatLLM, llm_from_env


def test_llm_from_env_needs_all_three_settings():
    assert llm_from_env({}) is None
    assert llm_from_env({"LLM_BASE_URL": "https://example.test/v1", "LLM_API_KEY": "k"}) is None


def test_llm_from_env_builds_a_client():
    llm = llm_from_env({"LLM_BASE_URL": "https://example.test/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m"})
    assert isinstance(llm, OpenAICompatLLM) and llm.model == "m"


def _client(monkeypatch, outcome):
    import openai
    from types import SimpleNamespace

    llm = OpenAICompatLLM("https://example.test/v1", "k", "m")

    def create(**kwargs):
        if isinstance(outcome, int):
            cls = {429: openai.RateLimitError, 500: openai.InternalServerError, 400: openai.BadRequestError}[outcome]
            error = cls.__new__(cls)  # built without the HTTP response object the constructor wants
            error.args = ("boom",)
            raise error
        return outcome

    monkeypatch.setattr(llm, "client", SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    return llm


def test_rate_limits_and_outages_are_unavailable(monkeypatch):
    import pytest
    from copilot.llm import LLMUnavailable
    for status in (429, 500):
        with pytest.raises(LLMUnavailable):
            _client(monkeypatch, status).chat([], [])


def test_a_rejected_request_is_not_reported_as_unavailable(monkeypatch):
    import pytest
    from copilot.llm import LLMRejected, LLMUnavailable
    with pytest.raises(LLMRejected):
        _client(monkeypatch, 400).chat([], [])
    assert not issubclass(LLMRejected, LLMUnavailable)


def test_a_response_without_choices_is_unavailable(monkeypatch):
    import pytest
    from types import SimpleNamespace
    from copilot.llm import LLMUnavailable
    with pytest.raises(LLMUnavailable):
        _client(monkeypatch, SimpleNamespace(choices=[], usage=None)).chat([], [])


def test_an_empty_assistant_turn_still_has_content(monkeypatch):
    from types import SimpleNamespace
    message = SimpleNamespace(content=None, tool_calls=None, model_dump=lambda exclude_none: {"role": "assistant"})
    turn = _client(monkeypatch, SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)).chat([], [])
    assert turn.message == {"role": "assistant", "content": ""}

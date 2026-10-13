from copilot.llm import OpenAICompatLLM, llm_from_env


def test_llm_from_env_needs_all_three_settings():
    assert llm_from_env({}) is None
    assert llm_from_env({"LLM_BASE_URL": "https://example.test/v1", "LLM_API_KEY": "k"}) is None


def test_llm_from_env_builds_a_client():
    llm = llm_from_env({"LLM_BASE_URL": "https://example.test/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m"})
    assert isinstance(llm, OpenAICompatLLM) and llm.model == "m"

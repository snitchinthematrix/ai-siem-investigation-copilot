from streamlit.testing.v1 import AppTest

from copilot.db import ROOT


def test_investigate_page_renders_without_an_llm(monkeypatch):
    for name in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REPLAY_DELAY", "0")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert not app.exception
    assert app.title[0].value == "SIEM Investigation Copilot"
    assert len(app.sidebar.radio[0].options) == 21
    assert app.sidebar.radio[1].disabled

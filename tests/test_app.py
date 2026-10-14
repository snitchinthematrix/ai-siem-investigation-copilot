from streamlit.testing.v1 import AppTest

from copilot.db import ROOT


def run_app(monkeypatch, llm=False):
    if not llm:
        for name in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REPLAY_DELAY", "0")
    return AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()


def test_investigate_page_renders_without_an_llm(monkeypatch):
    app = run_app(monkeypatch)
    assert not app.exception
    assert app.title[0].value == "SIEM Investigation Copilot"
    assert app.sidebar.radio[0].disabled
    # Opens on the first alert in the queue, with its recorded run.
    assert app.session_state["alert_id"] == "R001-00a56d94"
    assert any("Investigation trace" in heading.value for heading in app.subheader)
    assert any(heading.value == "Verdict" for heading in app.subheader)


def test_the_queue_lists_every_alert_and_marks_the_open_one(monkeypatch):
    app = run_app(monkeypatch)
    queue = app.dataframe[0].value
    assert len(queue) == 21
    assert queue["Alert ID"].is_unique
    assert list(queue[queue["Open"] == "●"]["Alert ID"]) == ["R001-00a56d94"]


def test_an_alert_opened_from_elsewhere_is_shown(monkeypatch):
    for name in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REPLAY_DELAY", "0")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state["alert_id"] = "R003-15a5656f"
    app.run()
    assert not app.exception
    assert any("R003-15a5656f" in block.value for block in app.markdown)


def test_filtering_the_queue_keeps_the_open_alert(monkeypatch):
    app = run_app(monkeypatch)
    app.selectbox[0].select("Registry Run key modified").run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 3
    assert app.session_state["alert_id"] == "R001-00a56d94"


def test_scorecard_page_renders():
    page = AppTest.from_file(str(ROOT / "views" / "scorecard.py"), default_timeout=60).run()
    assert not page.exception
    assert page.title[0].value == "Scorecard"
    assert [metric.label for metric in page.metric] == [
        "Verdict accuracy", "False alarms", "Valid citations", "Injections resisted"]

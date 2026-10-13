from copilot.render import plain, report


def test_plain_neutralizes_images_links_and_code_spans():
    text = plain("see ![x](http://evil.test/a.png) and [click](http://evil.test) `E1`")
    assert "![" not in text and "](" not in text
    assert chr(92) + "[" in text and chr(92) + "`" in text


def test_plain_handles_non_strings():
    assert plain(None) == ""
    assert plain(42) == "42"


def test_report_keeps_structure_but_not_links_or_images():
    text = report("## Summary\n- **bad** task ![x](http://evil.test/a.png) <img src=x>")
    assert text.startswith("## Summary\n- **bad** task")
    assert "![" not in text and chr(92) + "](" in text and chr(92) + "<img" in text

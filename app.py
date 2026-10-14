"""Entry point: page settings and navigation. The pages are in views/."""
import streamlit as st

st.set_page_config(page_title="SIEM Investigation Copilot", page_icon=":material/policy:", layout="wide")

st.navigation([
    st.Page("views/investigate.py", title="Investigate", icon=":material/search:", default=True),
    st.Page("views/scorecard.py", title="Scorecard", icon=":material/leaderboard:"),
]).run()

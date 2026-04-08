"""Agent definition for the Cybersecurity Log Triage Agent."""

from google.adk.agents import Agent

from .prompts import SYSTEM_PROMPT
from .tools import analyze_logs, generate_summary

root_agent = Agent(
    name="logs_triage_agent",
    model="gemini-2.5-flash",
    description=(
        "An AI cybersecurity analyst that triages raw log entries, "
        "detects attacks and vulnerabilities, assigns severity levels, "
        "and produces a structured JSON security report."
    ),
    instruction=SYSTEM_PROMPT,
    tools=[
        analyze_logs,
        generate_summary,
    ],
)

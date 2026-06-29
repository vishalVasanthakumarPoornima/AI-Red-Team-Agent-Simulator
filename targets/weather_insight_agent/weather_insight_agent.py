from functional_agents.graphs import GraphDependencyError, run_weather_agent


AGENT_NAME = "Weather Insight Agent"


def run_agent(prompt: str) -> str:
    try:
        return run_weather_agent(prompt)
    except GraphDependencyError as exc:
        return f"ERROR: {exc}"

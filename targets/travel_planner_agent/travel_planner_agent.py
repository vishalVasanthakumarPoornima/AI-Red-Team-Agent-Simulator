from functional_agents.graphs import GraphDependencyError, run_travel_agent


AGENT_NAME = "Travel Planner Agent"
REDTEAM_TARGET = True


def run_agent(prompt: str) -> str:
    try:
        return run_travel_agent(prompt)
    except GraphDependencyError as exc:
        return f"ERROR: {exc}"

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN useradd --create-home --uid 10001 redteam
COPY pyproject.toml README.md /app/
COPY redteam_platform /app/redteam_platform
COPY scanner /app/scanner
COPY functional_agents /app/functional_agents
COPY targets /app/targets
COPY agent_registry.py agent_registry.json /app/
RUN python -m pip install --no-cache-dir .

USER redteam
EXPOSE 18150
CMD ["redteam", "api", "serve"]

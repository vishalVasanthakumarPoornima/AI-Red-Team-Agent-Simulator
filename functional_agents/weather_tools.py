"""Weather lookup tools for functional lab agents."""

from datetime import datetime, timezone
import json
import os
from urllib.parse import urlencode
import urllib.error
import urllib.request


DEFAULT_TIMEOUT_SECONDS = 12


class ToolError(RuntimeError):
    """Expected external tool failure."""


def _get_json(url, timeout=DEFAULT_TIMEOUT_SECONDS):
    request = urllib.request.Request(url, headers={"User-Agent": "ai-red-team-lab/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ToolError(f"Weather lookup failed: {exc}") from exc


def _open_meteo_geocode(location):
    query = urlencode({"name": location, "count": 1, "language": "en", "format": "json"})
    data = _get_json(f"https://geocoding-api.open-meteo.com/v1/search?{query}")
    results = data.get("results") or []
    if not results:
        raise ToolError(f"No coordinates found for location '{location}'.")
    result = results[0]
    return {
        "name": result.get("name") or location,
        "country": result.get("country"),
        "latitude": result["latitude"],
        "longitude": result["longitude"],
        "provider": "open-meteo",
    }


def _openweather_geocode(location):
    api_key = os.environ.get("OPENWEATHER_API_KEY")
    if not api_key:
        return None
    query = urlencode({"q": location, "limit": 1, "appid": api_key})
    data = _get_json(f"https://api.openweathermap.org/geo/1.0/direct?{query}")
    if not data:
        raise ToolError(f"No coordinates found for location '{location}'.")
    result = data[0]
    return {
        "name": result.get("name") or location,
        "country": result.get("country"),
        "latitude": result["lat"],
        "longitude": result["lon"],
        "provider": "openweather",
    }


def geocode_location(location):
    location = " ".join(str(location or "").split())
    if not location:
        raise ToolError("Location is required.")
    return _openweather_geocode(location) or _open_meteo_geocode(location)


def get_weather_forecast(location, days=3):
    days = max(1, min(int(days or 3), 7))
    geo = geocode_location(location)
    query = urlencode(
        {
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
            "daily": "temperature_2m_max,temperature_2m_min,precipitation_probability_max,weather_code",
            "timezone": "auto",
            "forecast_days": days,
        }
    )
    forecast = _get_json(f"https://api.open-meteo.com/v1/forecast?{query}")
    daily = forecast.get("daily") or {}
    rows = []
    for index, date in enumerate(daily.get("time", [])):
        rows.append(
            {
                "date": date,
                "temperature_min_c": _at(daily.get("temperature_2m_min"), index),
                "temperature_max_c": _at(daily.get("temperature_2m_max"), index),
                "precipitation_probability_max": _at(
                    daily.get("precipitation_probability_max"), index
                ),
                "weather_code": _at(daily.get("weather_code"), index),
            }
        )

    return {
        "location": {
            "name": geo["name"],
            "country": geo.get("country"),
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
        },
        "provider": "open-meteo",
        "provider_key_configured": bool(os.environ.get("OPENWEATHER_API_KEY")),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "forecast": rows,
    }


def _at(values, index):
    if not values or index >= len(values):
        return None
    return values[index]

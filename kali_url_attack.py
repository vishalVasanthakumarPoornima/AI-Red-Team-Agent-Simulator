"""Run Kali recon and prompt probes against a hosted agent URL."""

from urllib.parse import urlparse
import json
import shlex

from kali_agent_attack import DEFAULT_PROBES, _run_remote, _summarize
from scanner.detectors import evaluate_response


ENDPOINT_PATHS = ("/", "/health", "/metadata", "/invoke", "/admin", "/metrics", "/debug")


def _base_url(url):
    return str(url).rstrip("/")


def _host_port(url):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("URL must include scheme and host, for example: https://example.onrender.com")
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80
    return parsed.hostname, port


def _endpoint_checks(host, timeout, identity_file, url):
    base = _base_url(url)
    script = "\n".join(
        [
            "set -u",
            f"base={shlex.quote(base)}",
            "for path in " + " ".join(shlex.quote(path) for path in ENDPOINT_PATHS) + "; do",
            "  code=$(curl -s -m 12 -o /tmp/kali_url_probe_body -w \"%{http_code}\" \"$base$path\")",
            "  printf \"%s %s\\n\" \"$code\" \"$path\"",
            "done",
        ]
    )
    return _run_remote(host, timeout, "bash -s", identity_file=identity_file, stdin=script)


def _web_recon(host, timeout, identity_file, url):
    target_host, target_port = _host_port(url)
    base = _base_url(url)
    return {
        "nmap": _run_remote(
            host,
            timeout,
            f"nmap -sV --version-light -p {target_port} {shlex.quote(target_host)}",
            identity_file=identity_file,
            command_timeout=90,
        ),
        "whatweb": _run_remote(
            host,
            timeout,
            f"whatweb -a 1 {shlex.quote(base)}",
            identity_file=identity_file,
            command_timeout=60,
        ),
        "nikto": _run_remote(
            host,
            timeout,
            f"timeout 60s nikto -h {shlex.quote(base)} -nointeractive",
            identity_file=identity_file,
            command_timeout=75,
        ),
    }


def _prompt_probe(host, timeout, identity_file, url, attack, prompt):
    payload = json.dumps({"attack": attack, "prompt": prompt})
    command = (
        f"printf '%s' {shlex.quote(payload)} | "
        f"curl -s -m 180 -H 'Content-Type: application/json' -d @- "
        f"{shlex.quote(_base_url(url) + '/invoke')}"
    )
    remote = _run_remote(host, timeout, command, identity_file=identity_file, command_timeout=210)
    parsed = None
    parse_error = None
    result = None
    if remote["returncode"] != 0:
        parse_error = remote["stderr"] or f"Remote command exited {remote['returncode']}."
    elif not remote["stdout"]:
        parse_error = "Remote command returned an empty response."
    else:
        try:
            parsed = json.loads(remote["stdout"])
            if isinstance(parsed, dict) and "status" in parsed:
                result = parsed
            elif isinstance(parsed, dict) and "response" in parsed:
                evaluation = evaluate_response(prompt, parsed["response"], attack)
                result = {"attack": attack, "prompt": prompt, "response": parsed["response"], **evaluation}
            else:
                parse_error = "JSON response did not contain status or response."
        except json.JSONDecodeError as exc:
            parse_error = str(exc)
    return {
        "target": _base_url(url),
        "attack": attack,
        "prompt": prompt,
        "remote": remote,
        "raw_response": parsed,
        "result": result,
        "parse_error": parse_error,
    }


def run_kali_url_attack(
    *,
    host,
    url,
    identity_file=None,
    ssh_timeout=8,
    report_path=None,
    skip_web_recon=False,
):
    report = {
        "target_url": _base_url(url),
        "kali_host": host,
        "web_recon": {},
        "endpoint_checks": None,
        "probes": [],
        "summary": {},
    }
    if not skip_web_recon:
        report["web_recon"] = _web_recon(host, ssh_timeout, identity_file, url)
    report["endpoint_checks"] = _endpoint_checks(host, ssh_timeout, identity_file, url)
    for attack, prompt in DEFAULT_PROBES:
        report["probes"].append(_prompt_probe(host, ssh_timeout, identity_file, url, attack, prompt))
    report["summary"] = _summarize(report["probes"])

    for probe in report["probes"]:
        result = probe.get("result") or {}
        status = result.get("status", "UNPARSED")
        severity = result.get("severity", "Unknown")
        reason = result.get("reason") or probe.get("parse_error") or "No result."
        print(f"{probe['attack']}: {status} ({severity}) - {reason}")

    summary = report["summary"]
    print(
        "Kali URL attack complete: "
        f"{summary['pass']} PASS, {summary['fail']} FAIL, "
        f"{summary['error']} ERROR, {summary['unparsed']} UNPARSED."
    )

    if report_path:
        from pathlib import Path

        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report: {path}")
    return report

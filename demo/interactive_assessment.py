#!/usr/bin/env python3
"""Run an assessment in a PTY, require explicit authorization, and stream safe live events."""

from __future__ import annotations

import argparse
import json
import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PROMPT_MARKERS = (
    b"Start the displayed plan?",
    b"[y/N]",
    b"[Y/n]",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--event-log")
    parser.add_argument("--report-root", required=True)
    parser.add_argument("--label", default="assessment")
    parser.add_argument("--authorization-mode", choices=("ask", "approve", "deny"), default="ask")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def run_directories(root: Path) -> set[Path]:
    try:
        return {path.resolve() for path in root.glob("run_*") if path.is_dir()}
    except OSError:
        return set()


def newest_new_run(root: Path, before: set[Path]) -> Path | None:
    candidates: list[Path] = []
    try:
        for path in root.glob("run_*"):
            if path.is_dir() and path.resolve() not in before:
                candidates.append(path)
    except OSError:
        return None
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime_ns)


def first(event: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = event.get(key)
        if value not in (None, "", [], {}):
            if isinstance(value, (str, int, float, bool)):
                return str(value)
    return ""


def safe_live_line(event: dict[str, Any]) -> str | None:
    """Render only high-level fields. Never print payloads, prompts, headers, or evidence."""
    name = first(event, "event", "event_type", "type", "action", "name", "phase")
    status = first(event, "status", "state", "outcome", "result")
    identifier = first(event, "probe_id", "step_id", "template_id", "adapter_id", "finding_id")
    category = first(event, "category", "coverage_category")
    tool = first(event, "tool", "tool_id", "adapter", "adapter_name")
    sequence = first(event, "sequence", "seq")

    combined = " ".join(part for part in (name, status, identifier, category, tool) if part).lower()
    if not combined:
        return None

    # Ignore extremely low-value heartbeat/debug events.
    if any(token in combined for token in ("heartbeat", "debug", "trace")):
        return None

    parts: list[str] = []
    if sequence:
        parts.append(f"#{sequence}")
    if name:
        parts.append(name.replace("_", " "))
    if identifier:
        parts.append(f"[{identifier}]")
    if category:
        parts.append(f"category={category.replace('_', ' ')}")
    if tool:
        parts.append(f"tool={tool}")
    if status:
        parts.append(f"status={status.replace('_', ' ')}")
    return " ".join(parts)


def tail_events(
    run_dir: Path | None,
    offset: int,
    event_log_handle: Any | None,
) -> int:
    if run_dir is None:
        return offset
    path = run_dir / "events.jsonl"
    if not path.exists():
        return offset
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            for raw in handle:
                offset = handle.tell()
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                line = safe_live_line(event)
                if line:
                    rendered = f"\n\033[1;35m[LIVE ATTACK]\033[0m {line}\n"
                    sys.stdout.write(rendered)
                    sys.stdout.flush()
                    if event_log_handle is not None:
                        event_log_handle.write(line + "\n")
                        event_log_handle.flush()
    except OSError:
        return offset
    return offset


def main() -> int:
    args = parse_args()
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    report_root = Path(args.report_root)
    before_runs = run_directories(report_root)

    event_log_handle = None
    if args.event_log:
        event_path = Path(args.event_log)
        event_path.parent.mkdir(parents=True, exist_ok=True)
        event_log_handle = event_path.open("w", encoding="utf-8")

    master_fd, slave_fd = pty.openpty()
    process = subprocess.Popen(
        args.command,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        env=os.environ.copy(),
    )
    os.close(slave_fd)

    buffer = bytearray()
    authorization_handled = False
    run_dir: Path | None = None
    event_offset = 0
    last_poll = 0.0

    try:
        with log_path.open("wb") as log_file:
            while True:
                ready, _, _ = select.select([master_fd], [], [], 0.15)
                if ready:
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError:
                        chunk = b""
                    if chunk:
                        log_file.write(chunk)
                        log_file.flush()
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                        buffer.extend(chunk)
                        if len(buffer) > 16384:
                            del buffer[:-16384]

                        if not authorization_handled and any(marker in buffer for marker in PROMPT_MARKERS):
                            authorization_handled = True
                            if args.authorization_mode == "approve":
                                os.write(master_fd, b"y\n")
                                print("\n\033[1;32m[AUTHORIZED]\033[0m Reusing the explicit authorization already entered for this exact plan and target.\n")
                            elif args.authorization_mode == "deny":
                                os.write(master_fd, b"n\n")
                                print("Assessment cancelled by launcher policy.")
                            else:
                                print("\n\n" + "=" * 72)
                                print("AUTHORIZATION REQUIRED")
                                print("Review the displayed target, scope, tools, requests, and limits.")
                                print("Type exactly AUTHORIZE to begin active testing.")
                                print("Anything else cancels the run.")
                                print("=" * 72)
                                try:
                                    response = input("Authorization: ").strip()
                                except (EOFError, KeyboardInterrupt):
                                    response = ""
                                os.write(master_fd, b"y\n" if response == "AUTHORIZE" else b"n\n")
                                if response != "AUTHORIZE":
                                    print("Assessment cancelled. No active test was authorized.")

                now = time.monotonic()
                if now - last_poll >= 0.25:
                    last_poll = now
                    if run_dir is None:
                        run_dir = newest_new_run(report_root, before_runs)
                        if run_dir is not None:
                            message = f"\n\033[1;32m[LIVE]\033[0m New {args.label} run: {run_dir.name}\n"
                            sys.stdout.write(message)
                            sys.stdout.flush()
                    event_offset = tail_events(run_dir, event_offset, event_log_handle)

                if process.poll() is not None:
                    # Drain remaining PTY output and final events.
                    while True:
                        try:
                            chunk = os.read(master_fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        log_file.write(chunk)
                        sys.stdout.buffer.write(chunk)
                    for _ in range(4):
                        if run_dir is None:
                            run_dir = newest_new_run(report_root, before_runs)
                        event_offset = tail_events(run_dir, event_offset, event_log_handle)
                        time.sleep(0.1)
                    break
    finally:
        os.close(master_fd)
        if event_log_handle is not None:
            event_log_handle.close()

    if run_dir is not None:
        print(f"\nRecorded run directory: {run_dir}")
    return int(process.returncode or 0)


if __name__ == "__main__":
    raise SystemExit(main())

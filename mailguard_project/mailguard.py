#!/usr/bin/env python3
"""MailGuard: a defensive, local .eml header analyzer (Python standard library only)."""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import parseaddr
from pathlib import Path
from typing import Any


def decode_value(value: str | None) -> str:
    if not value:
        return "(missing)"
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def parse_message(path: Path):
    try:
        with path.open("rb") as f:
            return BytesParser(policy=policy.default).parse(f)
    except OSError as exc:
        raise ValueError(f"Cannot read file: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Could not parse .eml: {exc}") from exc


def email_domain(value: str | None) -> str | None:
    if not value:
        return None
    _, addr = parseaddr(value)
    if "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip(" >.").lower() or None


def extract_ip(text: str) -> str | None:
    # Received fields commonly put IP addresses in square brackets.
    candidates = re.findall(r'\[([0-9a-fA-F:.]+)\]', text)
    candidates += re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text)
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def parse_received(msg) -> list[dict[str, str]]:
    # RFC order: newest hop first. Reverse for origin -> final delivery.
    raw = list(msg.get_all("Received", []))
    hops = []
    for idx, header in enumerate(reversed(raw), 1):
        text = str(header).replace("\r", " ").replace("\n", " ")
        left, sep, date_part = text.rpartition(";")
        if not sep:
            left, date_part = text, "(timestamp not found)"
        from_match = re.search(r'\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s+for\s+|$)', left, re.I)
        by_match = re.search(r'\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|\s+for\s+|$)', left, re.I)
        sending = from_match.group(1).strip(" ()") if from_match else "(unknown)"
        receiving = by_match.group(1).strip(" ()") if by_match else "(unknown)"
        hops.append({
            "number": str(idx),
            "sending": sending,
            "receiving": receiving,
            "ip": extract_ip(left) or "(not found)",
            "timestamp": date_part.strip() or "(not found)",
            "raw": text,
        })
    return hops


AUTH_RE = re.compile(
    r'\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?'
    r'|(?:header\.|smtp\.)?(?:from|d)=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    re.I,
)


def parse_authentication(msg) -> list[dict[str, str]]:
    results = []
    for header in msg.get_all("Authentication-Results", []):
        text = str(header)
        # Split into auth-method chunks so a domain parameter is associated with its method.
        matches = list(re.finditer(r'\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)', text, re.I))
        for i, match in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            chunk = text[match.start():end]
            domain_match = re.search(
                r'(?:header\.from|header\.d|smtp\.mailfrom|smtp\.helo|header\.i)\s*=\s*"?([^;\s"]+)',
                chunk, re.I
            )
            domain = domain_match.group(1).strip(" <>") if domain_match else "(not specified)"
            results.append({
                "method": match.group(1).lower(),
                "result": match.group(2).lower(),
                "domain": domain.lower(),
            })
    return results


def spoofing_checks(msg, hops, auth, known_good: list[str]) -> list[tuple[str, str]]:
    flags: list[tuple[str, str]] = []
    from_value = str(msg.get("From", ""))
    return_value = str(msg.get("Return-Path", ""))
    reply_value = str(msg.get("Reply-To", ""))
    from_domain = email_domain(from_value)
    return_domain = email_domain(return_value)
    reply_domain = email_domain(reply_value)

    if not from_value:
        flags.append(("HIGH", "From header is missing or invalid."))
    if from_domain and return_domain and from_domain != return_domain:
        flags.append(("MEDIUM", f"From domain ({from_domain}) differs from Return-Path domain ({return_domain})."))
    if from_domain and reply_domain and from_domain != reply_domain:
        flags.append(("LOW", f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}); verify expected reply routing."))

    authenticated_domains = {
        item["domain"].lower().strip(".")
        for item in auth
        if item["domain"] != "(not specified)" and item["result"] in {"pass"}
    }
    if from_domain and authenticated_domains and not any(
        from_domain == d or from_domain.endswith("." + d) or d.endswith("." + from_domain)
        for d in authenticated_domains
    ):
        flags.append(("HIGH", f"From domain ({from_domain}) does not match any passing authenticated domain ({', '.join(sorted(authenticated_domains))})."))

    for hop in hops:
        raw = hop["raw"].lower()
        if "localhost" in raw or "127.0.0.1" in raw or "[::1]" in raw:
            flags.append(("MEDIUM", f"Received hop {hop['number']} contains localhost/loopback; verify this is expected in your lab."))

    # Simple lookalike check against explicitly supplied known-good domains.
    if from_domain:
        for good in known_good:
            good = good.lower().strip()
            if not good or from_domain == good or from_domain.endswith("." + good):
                continue
            # Compare only domains of similar length; this is a heuristic, not proof.
            ratio = SequenceMatcher(None, from_domain, good).ratio()
            if ratio >= 0.82 and abs(len(from_domain) - len(good)) <= 3:
                flags.append(("HIGH", f"Sender domain {from_domain} resembles known-good domain {good} (similarity {ratio:.0%})."))
                break
    return flags


def determine_verdict(auth, flags) -> tuple[str, list[str]]:
    reasons = []
    auth_by_method = {}
    for item in auth:
        auth_by_method.setdefault(item["method"], []).append(item["result"])

    failed = []
    missing = []
    for method in ("spf", "dkim", "dmarc"):
        values = auth_by_method.get(method, [])
        if not values:
            missing.append(method.upper())
        elif any(v in {"fail", "permerror"} for v in values):
            failed.append(method.upper())

    if failed:
        reasons.append("Authentication failure: " + ", ".join(failed))
    if missing:
        reasons.append("No result found for: " + ", ".join(missing))
    for severity, reason in flags:
        reasons.append(f"{severity}: {reason}")

    if failed or any(sev == "HIGH" for sev, _ in flags):
        verdict = "FAIL"
    elif missing or any(sev in {"MEDIUM", "LOW"} for sev, _ in flags) or any(
        item["result"] not in {"pass"} for item in auth
    ):
        verdict = "SUSPICIOUS"
    else:
        verdict = "PASS"
    if not reasons:
        reasons.append("SPF, DKIM and DMARC report pass; no configured spoofing indicators were detected.")
    return verdict, reasons


def build_report(msg, hops, auth, flags, verdict_data) -> str:
    verdict, reasons = verdict_data
    lines = [
        "=" * 68,
        "MAILGUARD — EMAIL HEADER ANALYSIS REPORT",
        "=" * 68,
        "",
        "KEY HEADERS",
    ]
    for name in ("From", "To", "Subject", "Date", "Return-Path", "Reply-To"):
        lines.append(f"{name}: {decode_value(str(msg.get(name))) if msg.get(name) is not None else '(missing)'}")
    lines += ["", "RECEIVED RELAY CHAIN (origin -> final delivery)"]
    if not hops:
        lines.append("No Received headers found.")
    for hop in hops:
        lines += [
            f"Hop {hop['number']}: {hop['sending']} -> {hop['receiving']}",
            f"  Relay IP: {hop['ip']}",
            f"  Timestamp: {hop['timestamp']}",
        ]
    lines += ["", "AUTHENTICATION RESULTS (from Authentication-Results header)"]
    if not auth:
        lines.append("No authentication data found.")
    for item in auth:
        lines.append(f"{item['method'].upper()}: {item['result']} | domain: {item['domain']}")
    lines += ["", "SPOOFING / RELAY FLAGS"]
    if not flags:
        lines.append("No configured indicators detected.")
    for severity, reason in flags:
        lines.append(f"[{severity}] {reason}")
    lines += ["", f"FINAL VERDICT: {verdict}", "REASONS:"]
    for reason in reasons:
        lines.append(f"- {reason}")
    lines += ["", "NOTE: Header analysis is heuristic. Authentication-Results is supplied by a receiving system;"]
    lines.append("this offline tool does not independently query DNS or cryptographically verify DKIM signatures.")
    lines.append("=" * 68)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a locally-created or authorized .eml file. Does not connect to mail servers."
    )
    parser.add_argument("eml_file", help="Path to the .eml file")
    parser.add_argument("-o", "--output", default="mailguard_report.txt", help="Report output path")
    parser.add_argument(
        "--known-good", default="",
        help="Comma-separated known-good domains for lookalike comparison, e.g. example.com,company.test"
    )
    args = parser.parse_args()
    path = Path(args.eml_file)
    try:
        msg = parse_message(path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    hops = parse_received(msg)
    auth = parse_authentication(msg)
    known_good = [d.strip() for d in args.known_good.split(",") if d.strip()]
    flags = spoofing_checks(msg, hops, auth, known_good)
    verdict_data = determine_verdict(auth, flags)
    report = build_report(msg, hops, auth, flags, verdict_data)

    print(report, end="")
    try:
        Path(args.output).write_text(report, encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: Could not save report: {exc}", file=sys.stderr)
        return 3
    print(f"\nReport saved to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

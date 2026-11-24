# MailGuard — Email Header Analyzer

A local, command-line Python tool for analyzing `.eml` headers. It uses only the Python standard library.

## Requirements
- Python 3.10 or newer (3.9 may also work)
- No pip packages required

## Run
```bash
python mailguard.py samples/good.eml -o reports/good.txt --known-good example.com
```

Windows PowerShell:
```powershell
py -3 mailguard.py samples/good.eml -o reports/good.txt --known-good example.com
```

Create the reports folder first:
```bash
mkdir reports
```

## Features
- Parses From, To, Subject, Date, Return-Path and Reply-To.
- Displays Received hops in origin-to-destination order, with best-effort host/IP/time extraction.
- Parses SPF, DKIM and DMARC entries in Authentication-Results.
- Flags selected From/Return-Path/Reply-To/authenticated-domain mismatches, localhost/loopback hops, and lookalike domains against domains supplied with `--known-good`.
- Produces PASS / SUSPICIOUS / FAIL and saves a text report.

## Test examples
```bash
python mailguard.py samples/good.eml -o reports/good.txt --known-good example.com
python mailguard.py samples/suspicious.eml -o reports/suspicious.txt --known-good example.com
python mailguard.py samples/spoofed.eml -o reports/spoofed.txt --known-good example.com
python mailguard.py samples/missing_auth.eml -o reports/missing_auth.txt
python mailguard.py samples/malformed.eml -o reports/malformed.txt
```

Expected high-level outcomes:
- `good.eml`: PASS
- `suspicious.eml`: SUSPICIOUS (partial auth / mismatch / loopback)
- `spoofed.eml`: FAIL (authentication failures and spoofing indicators)
- `missing_auth.eml`: SUSPICIOUS (no authentication data)
- `malformed.eml`: should parse without crashing; missing fields are reported.

## Important limitations
This is a header analyzer, not a full email-authentication verifier. It reads the Authentication-Results header; it does not perform DNS lookups for SPF/DMARC or cryptographically verify DKIM. Received parsing is best-effort because real-world Received syntax varies. A private or loopback IP is not automatically malicious; the loopback warning is only a prompt to verify lab context. Lookalike matching is heuristic and depends on the known-good domains you provide.

Only use self-created sample messages or mail from your own isolated lab server. Do not inspect other people's mailboxes or messages without explicit written permission.

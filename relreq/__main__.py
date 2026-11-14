"""CLI. inspect already works; verify and sign are the pieces to implement."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from relreq.load import LoadError, load_exchange, load_keys, load_policy, signature_header_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="relreq")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show request target, status, and signature headers")
    ins.add_argument("--exchange", required=True)
    ver = sub.add_parser("verify", help="verify response signatures and the bound request signature")
    ver.add_argument("--exchange", required=True)
    ver.add_argument("--keys", required=True)
    ver.add_argument("--policy", required=True)
    ver.add_argument("--report", required=True)
    sgn = sub.add_parser("sign", help="add a related-request response signature")
    sgn.add_argument("--exchange", required=True)
    sgn.add_argument("--keys", required=True)
    sgn.add_argument("--policy", required=True)
    sgn.add_argument("--output", required=True)
    sgn.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        exchange = load_exchange(args.exchange)
    except (LoadError, OSError, KeyError, ValueError) as exc:
        print(f"failed to load exchange: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        req = exchange["request"]
        print(json.dumps({
            "request_method": req["method"],
            "request_authority": req["authority"],
            "request_path": req["path"],
            "request_query": req.get("query", ""),
            "request_now": req["now"],
            "status": exchange["status"],
            "now": exchange["now"],
            "request_signature_input": signature_header_text(req.get("headers") or []),
            "response_signature_input": signature_header_text(exchange.get("headers") or []),
            "response_body_chars": len(exchange.get("body") or ""),
        }, ensure_ascii=False, indent=2))
        return 0
    try:
        keys = load_keys(args.keys)
        policy = load_policy(args.policy)
    except (LoadError, OSError) as exc:
        print(f"failed to load keys or policy: {exc}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "verify":
            from relreq.engine import verify
            report = verify(exchange, keys, policy)
            if isinstance(report, dict):
                report.setdefault('input', args.exchange)
                report.setdefault("policy", args.policy)
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            decision = str(report.get("decision", "")).lower()
            if decision == "ok":
                return 0
            if decision == "reject":
                return 1
            print("report is missing a decision of ok or reject", file=sys.stderr)
            return 2
        if args.cmd == "sign":
            from relreq.engine import sign
            output, report = sign(exchange, keys, policy)
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            if isinstance(report, dict):
                report.setdefault('input', args.exchange)
                report.setdefault("policy", args.policy)
            Path(args.output).write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            decision = str(report.get("decision", "")).lower()
            if decision == "ok":
                return 0
            if decision == "reject":
                return 1
            print("report is missing a decision of ok or reject", file=sys.stderr)
            return 2
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

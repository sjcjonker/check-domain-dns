#!/usr/bin/env python3
"""Nagios DNS record integrity checker (requires python3-dnspython)."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone

try:
    import dns.exception
    import dns.resolver
except ImportError:
    print("UNKNOWN - missing dnspython; install python3-dnspython")
    sys.exit(3)

OK, WARNING, CRITICAL, UNKNOWN = range(4)
EXCLUDES = {"apex", "ns", "mx", "caa", "www"}


def domain_name(value):
    name = value.strip().rstrip(".").lower()
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(name) > 253 or not re.fullmatch(rf"(?:{label}\.)+{label}", name):
        raise argparse.ArgumentTypeError("invalid domain")
    return name


def make_plan(domain, excludes):
    plan = {}
    for typ in ("NS", "MX", "CAA"):
        if typ.lower() not in excludes:
            plan[f"{domain}.|{typ}"] = (domain + ".", typ)
    for scope, name in (("apex", domain), ("www", "www." + domain)):
        if scope not in excludes:
            for typ in ("A", "AAAA"):
                plan[f"{name}.|{typ}"] = (name + ".", typ)
    return plan


def canonical(record, typ):
    if typ == "NS":
        return record.target.to_text().lower()
    if typ == "MX":
        return f"{record.preference} {record.exchange.to_text().lower()}"
    if typ in ("A", "AAAA"):
        return str(ipaddress.ip_address(record.address))
    if typ == "CAA":
        return f"{record.flags} {record.tag.decode('ascii').lower()} {record.value.hex()}"
    raise ValueError(typ)


def resolver_for(server, timeout):
    resolver = dns.resolver.Resolver(configure=server is None)
    if server:
        resolver.nameservers = [server]
    resolver.timeout = min(timeout, 3)
    resolver.lifetime = timeout
    resolver.use_search_by_default = False
    return resolver


def query_plan(plan, resolver):
    records, errors = {}, {}
    for key, (name, typ) in plan.items():
        try:
            answer = resolver.resolve(name, typ, search=False, raise_on_no_answer=False)
            records[key] = sorted({canonical(record, typ) for record in answer}) if answer.rrset is not None else []
        except (dns.exception.DNSException, OSError) as exc:
            errors[key] = f"{type(exc).__name__}: {exc}"
    return records, errors


def differences(expected, actual):
    changes = []
    for key in sorted(expected.keys() & actual.keys()):
        old, new = set(expected[key]), set(actual[key])
        if old != new:
            parts = []
            if new - old:
                parts.append("added " + ",".join(sorted(new - old)))
            if old - new:
                parts.append("removed " + ",".join(sorted(old - new)))
            changes.append(f"{key}: " + "; ".join(parts))
    return changes


def state_path(directory, domain):
    return Path(directory) / (domain + ".json")


def save_state(path, document, overwrite):
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("baseline path must not be a symlink")
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists; use --update")
    fd, temporary = tempfile.mkstemp(prefix=".dns-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o640)
            json.dump(document, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_state(path, domain):
    if path.is_symlink():
        raise ValueError("baseline path must not be a symlink")
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema") != 1 or data.get("domain") != domain:
        raise ValueError("invalid baseline schema or domain")
    excludes = data.get("exclude")
    if not isinstance(excludes, list) or any(x not in EXCLUDES for x in excludes):
        raise ValueError("invalid baseline exclusions")
    plan = make_plan(domain, set(excludes))
    records = data.get("records")
    if not isinstance(records, dict) or set(records) != set(plan) or any(
        not isinstance(value, list) or any(not isinstance(item, str) for item in value)
        for value in records.values()
    ):
        raise ValueError("invalid baseline records")
    return data, plan


def report(status, summary, details=()):
    label = ("OK", "WARNING", "CRITICAL", "UNKNOWN")[status]
    print(f"{label} - {summary}")
    for detail in details:
        print(str(detail).replace("\n", " ")[:1200])
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", type=domain_name)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--baseline", "--initial", action="store_true")
    modes.add_argument("--update", action="store_true")
    parser.add_argument("--exclude", action="append", default=[], help="comma-separated: apex,ns,mx,caa,www")
    servers = parser.add_mutually_exclusive_group()
    servers.add_argument("--single-check", metavar="IP")
    servers.add_argument("--double-check", metavar="IP")
    parser.add_argument("--state-dir", default="/var/lib/nagios4/check-domain-dns")
    parser.add_argument("--timeout", type=float, default=4)
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 30:
        parser.error("--timeout must be greater than 0 and no more than 30")
    for server in (args.single_check, args.double_check):
        if server:
            try:
                ipaddress.ip_address(server)
            except ValueError:
                parser.error("resolver must be an IP address")
    excludes = {item.strip().lower() for entry in args.exclude for item in entry.split(",")}
    if excludes - EXCLUDES:
        parser.error("invalid --exclude: " + ",".join(sorted(excludes - EXCLUDES)))
    if excludes and not (args.baseline or args.update):
        parser.error("--exclude only valid for --baseline or --update")
    path = state_path(args.state_dir, args.domain)
    resolver_mode = (
        f"single-check {args.single_check}" if args.single_check
        else f"double-check local + {args.double_check}" if args.double_check
        else "local resolver"
    )

    def report_mode(status, summary, details=()):
        return report(status, f"{summary} [resolver: {resolver_mode}]", details)

    try:
        if args.baseline or args.update:
            if args.update:
                stored, _ = load_state(path, args.domain)
                if not excludes:
                    excludes = set(stored["exclude"])
            plan = make_plan(args.domain, excludes)
            if not plan:
                return report_mode(UNKNOWN, "no record groups selected")
        else:
            stored, plan = load_state(path, args.domain)
        records, errors = query_plan(plan, resolver_for(args.single_check, args.timeout))
        if errors:
            return report_mode(WARNING, f"{args.domain}: {len(errors)} DNS query failures", [f"{k}: {v}" for k, v in sorted(errors.items())])
        if args.double_check:
            other, errors = query_plan(plan, resolver_for(args.double_check, args.timeout))
            if errors:
                return report_mode(WARNING, f"{args.domain}: public resolver failed", [f"{k}: {v}" for k, v in sorted(errors.items())])
            diff = differences(records, other)
            if diff:
                return report_mode(CRITICAL, f"{args.domain}: local DNS differs from {args.double_check}", diff)
        if args.baseline or args.update:
            save_state(path, {
                "schema": 1, "domain": args.domain, "exclude": sorted(excludes),
                "updated_utc": datetime.now(timezone.utc).isoformat(), "records": records
            }, overwrite=args.update)
            return report_mode(OK, f"{args.domain}: baseline {'updated' if args.update else 'created'} ({len(records)} record sets)")
        diff = differences(stored["records"], records)
        if diff:
            return report_mode(CRITICAL, f"{args.domain}: {len(diff)} DNS record sets changed", diff)
        return report_mode(OK, f"{args.domain}: {len(records)} DNS record sets match baseline")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return report_mode(UNKNOWN, f"{args.domain}: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    sys.exit(main())

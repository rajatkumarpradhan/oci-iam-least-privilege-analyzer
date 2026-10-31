import argparse
import json
from pathlib import Path

from .parser import load_export
from .analysis import analyze
from .mapping import MappingError, load_mapping, load_required, suggest


def _write(report, output):
    text = json.dumps(report, indent=2) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def main(argv=None):
    argv = list(argv or [])
    import sys
    if not argv and sys.argv[1:2] == ["suggest"]:
        argv = ["suggest"] + sys.argv[2:]
    if argv[:1] == ["suggest"]:
        parser = argparse.ArgumentParser(prog="oci-iam-analyzer suggest",
                                         description="Draft least-privilege candidates from a versioned permission mapping (never applies anything)")
        parser.add_argument("export", help="JSON policy export, e.g. examples/synthetic.json")
        parser.add_argument("--requires", required=True, help="JSON workload required-operations file, e.g. examples/required-ops.json")
        parser.add_argument("--mapping", help="permission mapping JSON; default is the packaged versioned core-services mapping")
        parser.add_argument("--output", help="report JSON path; default stdout")
        args = parser.parse_args(argv[1:])
        try:
            report = suggest(load_mapping(args.mapping), load_export(args.export),
                             load_required(args.requires))
        except (OSError, ValueError, json.JSONDecodeError, MappingError) as exc:
            parser.error(str(exc))
        _write(report, args.output)
        return 0
    parser = argparse.ArgumentParser(description="Offline OCI IAM statement review")
    parser.add_argument("export", help="JSON policy export, e.g. examples/synthetic.json")
    parser.add_argument("--output", help="report JSON path; default stdout")
    parser.add_argument("--fail-on-manual-review", action="store_true", help="return 2 when any statement could not be classified")
    args = parser.parse_args(argv if argv else None)
    try:
        report = analyze(load_export(args.export))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    _write(report, args.output)
    return 2 if args.fail_on_manual_review and report["summary"]["manual_review"] else 0

if __name__ == "__main__":
    raise SystemExit(main())

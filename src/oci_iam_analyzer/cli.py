import argparse
import json
from .parser import load_export
from .analysis import analyze


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline OCI IAM statement review")
    parser.add_argument("export", help="JSON policy export, e.g. examples/synthetic.json")
    parser.add_argument("--output", help="report JSON path; default stdout")
    parser.add_argument("--fail-on-manual-review", action="store_true", help="return 2 when any statement could not be classified")
    args = parser.parse_args(argv)
    try:
        report = analyze(load_export(args.export))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 2 if args.fail_on_manual_review and report["summary"]["manual_review"] else 0

if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line interface for weblogchecker.

Usage:
    weblogchecker analyze <access.log> [--since YYYY-MM-DD]
                          [--baseline <older.log>]
                          [--format text|json]

Exit codes: 0 = no indicators found, 1 = indicators found,
2 = usage error (bad arguments, unreadable file).
"""

import argparse
import json
import sys
from datetime import datetime

from . import __version__
from .analyze import Analyzer, collect_baseline, open_log
from .render import render_text


def _parse_since(text):
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError(
            "--since must be a date as YYYY-MM-DD, got %r" % text)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="weblogchecker",
        description="Analyze web server access logs you own for "
                    "compromise indicators (webshell interactions, "
                    "exploitation patterns, brute-force bursts). "
                    "Read-only; reports indicators with confidence "
                    "levels, never verdicts of compromise.")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command")
    analyze = sub.add_parser(
        "analyze", help="analyze an access log file ('-' for stdin, "
                        ".gz files are decompressed automatically)")
    analyze.add_argument("logfile")
    analyze.add_argument("--since", type=_parse_since, default=None,
                         metavar="YYYY-MM-DD",
                         help="only analyze entries on/after this date")
    analyze.add_argument("--baseline", default=None,
                         metavar="LOGFILE",
                         help="trusted older access log: report "
                              "executable paths that appear for the "
                              "first time versus it, scored on "
                              "stacked weak signals")
    analyze.add_argument("--format", choices=("text", "json"),
                         default="text")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "analyze":
        parser.print_help(sys.stderr)
        return 2
    baseline_paths = None
    if args.baseline is not None:
        if args.baseline == "-" and args.logfile == "-":
            print("weblogchecker: --baseline and the analyzed log "
                  "cannot both be stdin", file=sys.stderr)
            return 2
        try:
            baseline_stream = open_log(args.baseline)
        except OSError as exc:
            print("weblogchecker: cannot open baseline %s: %s"
                  % (args.baseline, exc), file=sys.stderr)
            return 2
        try:
            with baseline_stream:
                baseline_paths, _ = collect_baseline(baseline_stream)
        except OSError as exc:
            print("weblogchecker: error reading baseline %s: %s"
                  % (args.baseline, exc), file=sys.stderr)
            return 2
    try:
        stream = open_log(args.logfile)
    except OSError as exc:
        print("weblogchecker: cannot open %s: %s"
              % (args.logfile, exc), file=sys.stderr)
        return 2
    analyzer = Analyzer(since=args.since,
                        baseline_paths=baseline_paths,
                        baseline_name=args.baseline)
    try:
        with stream:
            analyzer.run(stream)
    except OSError as exc:
        print("weblogchecker: error reading %s: %s"
              % (args.logfile, exc), file=sys.stderr)
        return 2
    report = analyzer.report(args.logfile, __version__)
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render_text(report))
    return 1 if report["findings"] else 0


def cli():
    """Console-script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    cli()

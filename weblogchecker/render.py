"""Human-readable text rendering of a weblogchecker report."""

_WIDTH = 78


def _wrap(text, indent="   "):
    import textwrap
    return "\n".join(
        textwrap.wrap(text, width=_WIDTH, initial_indent=indent,
                      subsequent_indent=indent)) 


def render_text(report):
    stats = report["stats"]
    summary = report["summary"]
    lines = []
    lines.append("weblogchecker %s - access-log compromise analysis"
                 % report["version"])
    lines.append("Log: %s" % report["log"])
    baseline = report.get("baseline")
    if baseline:
        lines.append(
            "Baseline: %s (%d executable paths known; executables "
            "absent from it are reported as NEW)"
            % (baseline["log"], baseline["executable_paths"]))
    if report.get("since"):
        lines.append("Since: %s (entries before this date were skipped)"
                     % report["since"])
    lines.append(
        "Lines read: %d | parsed: %d | unparseable (skipped): %d"
        % (stats["lines_read"], stats["entries_parsed"],
           stats["lines_skipped"]))
    if stats.get("entries_before_since"):
        lines.append("Entries skipped by --since: %d"
                     % stats["entries_before_since"])
    if stats.get("first_entry"):
        lines.append("Window analyzed: %s .. %s"
                     % (stats["first_entry"], stats["last_entry"]))
    lines.append("")
    lines.append(_wrap(report["verdict"], indent=""))
    lines.append("")

    if not report["findings"]:
        lines.append("Findings: none.")
        return "\n".join(lines) + "\n"

    by = summary["by_severity"]
    lines.append(
        "SUMMARY: %d findings (%d high, %d medium, %d low) across "
        "%d incidents, %d IPs flagged"
        % (summary["total_findings"], by["high"], by["medium"],
           by["low"], summary["incidents"], summary["ips_flagged"]))
    lines.append("")
    lines.append("INCIDENT TIMELINE (grouped by IP + path):")
    for incident in report["incidents"]:
        path = incident["path"] or "(many paths)"
        lines.append("  [%s] %s %s" % (incident["severity"].upper(),
                                       incident["ip"], path))
        lines.append("       classes: %s | requests: %d | %s .. %s"
                     % (", ".join(incident["classes"]),
                        incident["requests"], incident["first_seen"],
                        incident["last_seen"]))
    lines.append("")
    lines.append("FINDINGS (severity order; indicators, not proof):")
    for idx, finding in enumerate(report["findings"], 1):
        path = finding["path"] or "(many paths)"
        lines.append("")
        delta = " [%s]" % finding["delta"] if finding.get("delta") else ""
        lines.append("%d. [%s severity / %s confidence]%s %s"
                     % (idx, finding["severity"], finding["confidence"],
                        delta, finding["title"]))
        lines.append("   %s %s - %d request(s), %s .. %s"
                     % (finding["ip"], path, finding["count"],
                        finding["first_seen"], finding["last_seen"]))
        if finding.get("detail"):
            lines.append(_wrap("Detail: " + finding["detail"]))
        signals = finding.get("signals")
        if signals:
            fired = [name for name, on in signals.items() if on]
            lines.append(_wrap(
                "Signals fired: %s"
                % (", ".join(fired) if fired else "none")))
        for evidence in finding["evidence"]:
            lines.append("   | " + evidence)
        lines.append(_wrap("Remediation: " + finding["remediation"]))
    lines.append("")
    lines.append(
        "Companion tool: phpscan hunt scans the webroot itself for "
        "the shells these log patterns point at - "
        "pip install phpscan (github.com/PHPatch/phpscan).")
    return "\n".join(lines) + "\n"

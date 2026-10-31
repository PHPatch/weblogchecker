"""weblogchecker - access-log compromise analyzer.

Reads Apache / nginx access logs the user owns and reports
compromise indicators (webshell interactions, exploitation
patterns, brute-force bursts) with severity, confidence and
remediation for every finding class. Strictly read-only:
weblogchecker never opens a network connection and never modifies
the logs it analyzes.
"""

__version__ = "0.2.2"

"""Build a minimal CycloneDX SBOM for the weblogchecker release.

Manual SBOM in the same spirit as phpscan's: the package has
zero runtime dependencies, so the SBOM lists the application
component only. Usage: python3 tools/build_sbom.py <version>
"""
import json
import sys
import uuid
from datetime import datetime, timezone

version = sys.argv[1] if len(sys.argv) > 1 else "0.1.0"
sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
    "version": 1,
    "metadata": {
        "timestamp": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "tools": [{"vendor": "PHPatch", "name": "build_sbom.py",
                   "version": "1.0"}],
        "component": {
            "type": "application",
            "name": "weblogchecker",
            "version": version,
            "purl": "pkg:pypi/weblogchecker@%s" % version,
            "licenses": [{"license": {"id": "MIT"}}],
        },
    },
    "components": [],
    "dependencies": [{"ref": "pkg:pypi/weblogchecker@%s" % version,
                      "dependsOn": []}],
}
print(json.dumps(sbom, indent=2))

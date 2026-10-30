# Security

Report vulnerabilities in this tool through
https://phpatch.com/security or by email to
security@phpatch.com. Please do not open public issues for
vulnerabilities.

## Verifying releases

Release artifacts on GitHub are signed with the PHPatch
Security PGP key:

    PHPatch Security <security@phpatch.com>
    Fingerprint: BAA1 586A AD37 18C0 CE41 D288 FE23 A624 54E3 5307

The public key is `pgp-key.asc` in this repository. Verify with:

    gpg --import pgp-key.asc
    gpg --verify weblogchecker-0.1.0.tar.gz.asc weblogchecker-0.1.0.tar.gz

## Response commitments

- **Acknowledgement:** within 2 business days of your report.
- **Critical vulnerabilities:** a fix or mitigation within
  7 days of acknowledgement.
- **High-severity vulnerabilities:** a fix or mitigation within
  30 days of acknowledgement.

Lower-severity issues are fixed in the normal release flow.
We will credit reporters who ask to be credited, and we will
not pursue legal action against researchers who follow this
policy.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No - please upgrade |

# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories on
[Voltry-tech/voltry-probe](https://github.com/Voltry-tech/voltry-probe): open the Security
tab and use the "Report a vulnerability" button.

Do not open a public issue for a suspected signature bypass, verification
flaw, or key-handling problem. These packages exist to make cryptographic
claims about hardware; a public report of a way around those claims puts
every published certificate at risk before a fix can ship.

You will get an acknowledgment within 72 hours.

## Supported versions

The latest release of each package receives security fixes. Older releases
do not.

## Scope

This policy covers `voltry-probe` and `voltry-evidence-schema` as published
on PyPI: evidence capture, bundle signing and verification, attestation
report verification, and the offline certificate renderer.

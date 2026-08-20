# Security Policy

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue, pull
request, or discussion. Use GitHub's private vulnerability reporting form:

<https://github.com/crypt0rr/SpeeDNS/security/advisories/new>

If private reporting is unavailable, contact the repository owner through
GitHub and request a private channel. Do not include DNS query names, internal
resolver addresses, access tokens, signing credentials, or other sensitive
network information in the initial report.

Please include:

- the affected SpeeDNS version, commit, or release asset;
- the operating system and architecture;
- a concise description of the security impact;
- reproducible steps or a minimal offline fixture;
- any proposed mitigation, if known.

The maintainers will acknowledge a report when practical, investigate it, and
coordinate a fix and disclosure timeline with the reporter. There is no
guaranteed response or disclosure SLA.

## Scope

Reports about the SpeeDNS source, transport validation, parser handling,
release workflows, package artifacts, signing, and privacy behavior are in
scope. The following are generally outside the project's control:

- availability, filtering, routing, or policy behavior of public DNS
  providers;
- rate limiting or blocking imposed by a local network, ISP, VPN, firewall, or
  resolver operator;
- vulnerabilities in an operating system or third-party dependency that do
  not affect SpeeDNS through a reachable code path.

Dependency reports are still welcome when the affected dependency is reachable
in a supported SpeeDNS build; include the advisory identifier and installed
version.

## Supported versions

Security fixes target the current development branch and the latest published
prerelease or stable release. Older release artifacts may receive fixes on a
best-effort basis. SpeeDNS never changes system DNS settings and does not send
telemetry; reports should preserve that behavior.

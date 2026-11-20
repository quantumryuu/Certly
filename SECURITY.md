# Security Policy

This app stores CA private keys. A vulnerability in it can compromise every service that trusts those CAs, so security reports are taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
Go to the repository's **Security** tab and click **Report a vulnerability**.

Please include:
- the affected version or commit
- steps to reproduce, or a proof of concept
- the impact you expect (e.g. key disclosure, auth bypass, forged certificate)

You can expect a first response within 7 days. Once a fix is released, the issue will be disclosed in a GitHub Security Advisory, with credit to you unless you'd rather stay anonymous.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope:
- authentication or session bypass
- CSRF
- XSS
- injection
- private key or master key disclosure
- issuing certificates that weren't authorized
- revocation or CRL bypass
- backup or restore flaws (e.g. zip slip)
- weak cryptography

Out of scope:
- problems that need an attacker who already has root on the host or holds the master key
- running the app exposed to the internet against the guidance in the README
- denial of service from an authenticated admin

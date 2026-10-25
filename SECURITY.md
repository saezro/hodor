# Security Policy

## Supported versions

Only the latest released version of hodor receives security fixes. There is
no long-term support branch while the project is pre-1.0.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report it privately through
[GitHub Security Advisories](https://github.com/saezro/hodor/security/advisories/new)
for this repository. This lets us discuss and fix the issue before it is
publicly disclosed.

Include, where possible:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal `hodor.yaml` helps a lot).
- The hodor version or commit affected.

## What to expect

- Acknowledgement within a few days.
- A fix or mitigation plan communicated through the advisory thread.
- Credit in the advisory and `CHANGELOG.md`, unless you prefer to stay
  anonymous.

## Scope

In scope: hodor's core (listeners, proxy, forwardauth, pass/PIN signing,
admin API, config validation) and the official Docker image.

Out of scope: vulnerabilities in third-party software you run alongside
hodor (Traefik, Caddy, nginx, cloudflared), or issues requiring an attacker
to already control your LAN/VPN or admin credentials.

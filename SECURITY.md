# Security Policy

## Reporting a vulnerability

Please do **not** open a public GitHub issue for an unpatched vulnerability in
Gatekeeper.

Use GitHub's private vulnerability reporting feature for this repository when
available. If private reporting is unavailable, contact the repository owner
privately through the contact method listed on the GitHub profile.

Include enough detail to reproduce and assess the issue:

- affected version or commit;
- affected command/component;
- reproduction steps or proof of concept;
- expected security impact;
- any suggested mitigation.

## Scope

High-priority reports include:

- archive/path traversal or unsafe package extraction;
- integrity-verification bypasses;
- unintended execution of analyzed dependency code;
- network requests from workflows documented as offline;
- trust-baseline comparison errors that can hide high-risk drift;
- command injection or unsafe handling of untrusted repository/package data.

## Supported versions

Until the first stable release, only the latest released version and current
`main` are expected to receive security fixes.

Please allow a reasonable remediation window before public disclosure.

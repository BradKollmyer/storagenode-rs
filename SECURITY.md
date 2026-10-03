# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Email **rises_gall_4w@icloud.com** with a description of the issue, its impact, and
a reproduction if possible. You should receive an acknowledgement, and we will
keep you informed while a fix is prepared.

You can also report privately through GitHub:
[Security advisories](https://github.com/BradKollmyer/storagenode-rs/security/advisories/new).

This node holds an operator identity, a Noise key, S3 credentials, and piece
bytes. Treat those as secrets. Do not commit production keys or satellite
certificates.

## Supported versions

The `main` branch receives security fixes.

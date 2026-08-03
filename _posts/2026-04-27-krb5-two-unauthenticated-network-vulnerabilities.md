---
title: "Advisory - Kerberos (krb5) Two Unauthenticated Network Vulnerabilities: CVE-2026-40355 & CVE-2026-40356"
layout: post
---

## Management Summary

Two unauthenticated network vulnerabilities were identified in [MIT Kerberos
(krb5)](https://kerberos.org/about/FAQ.html). A crafted packet could cause a
null pointer dereference and terminate the process, and a separate crafted
packet could trigger a read overrun of up to 52 bytes. The issues were fixed
upstream in [commit
`2e75f0d`](https://github.com/krb5/krb5/commit/2e75f0d9362fb979f5fc92829431a590a130929f).

## Downstream Advisories

After upstream disclosure, the issues were referenced by major OS and platform
vendors, including Microsoft, Red Hat/Fedora, Oracle Linux, SUSE, Debian,
Ubuntu, and Amazon Linux, reflecting the broad deployment of Kerberos across
enterprise authentication stacks.

Selected downstream references:

- Microsoft MSRC: [CVE-2026-40355](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40355), [CVE-2026-40356](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40356)
- Red Hat: [CVE-2026-40355 and CVE-2026-40356 in Red Hat security data](https://access.redhat.com/hydra/rest/securitydata/cve)
- Fedora: [krb5-libs 1.22.2-4.fc43](https://packages.fedoraproject.org/pkgs/krb5/krb5-libs/fedora-43-updates-testing.html)
- Oracle Linux: [ELSA-2026-16799](https://linux.oracle.com/errata/ELSA-2026-16799.html)
- SUSE: [CVE-2026-40356](https://www.suse.com/security/cve/CVE-2026-40356.html)
- Debian: [CVE-2026-40355](https://security-tracker.debian.org/tracker/CVE-2026-40355), [CVE-2026-40356](https://security-tracker.debian.org/tracker/CVE-2026-40356)
- Ubuntu: [CVE-2026-40355](https://ubuntu.com/security/CVE-2026-40355), [CVE-2026-40356](https://ubuntu.com/security/CVE-2026-40356)
- Amazon Linux: [CVE-2026-40356](https://explore.alas.aws.amazon.com/CVE-2026-40356.html)

## Vendor / Project Description

MIT Kerberos (krb5) is an open-source network authentication protocol and
software implementation originally developed at MIT. According to the official
[MIT Kerberos FAQ](https://kerberos.org/about/FAQ.html), Kerberos is built into
all major operating systems, serves as the authentication mechanism for
Microsoft Active Directory, and is conservatively estimated to be used by well
[**over 100 million people worldwide**](https://kerberos.org/about/FAQ.html#:~:text=over%20100%20million%20people). 

The FAQ also describes Kerberos as one of
the most widely adopted authentication technologies in computer networking, and
states that one organization alone uses the MIT Kerberos software for over 50
million unique logons per month.

The project is also integrated into [Google's
OSS-Fuzz](https://google.github.io/oss-fuzz/#:~:text=Google%20created%20OSS%2DFuzz%20to%20fill%20this%20gap%3A%20it%E2%80%99s%20a%20free%20service%20that%20runs%20fuzzers%20for%20open%20source%20projects%20and%20privately%20alerts%20developers%20to%20the%20bugs%20detected)
continuous fuzzing service. 

## Technical Details

The vulnerable code is in:

[`src/lib/gssapi/spnego/negoex_util.c`](https://github.com/krb5/krb5/blob/2e75f0d9362fb979f5fc92829431a590a130929f/src/lib/gssapi/spnego/negoex_util.c)

### CVE-2026-40355: Null pointer dereference

In `parse_nego_message()`, the result of the second `vector_base()` call was
not checked before being dereferenced.

Impact: an unauthenticated remote attacker can trigger a null pointer
dereference and cause the process to terminate.

### CVE-2026-40356: Read overrun

In `parse_message()`, a short `header_len` could cause an integer underflow
while calculating the remaining message length.

Impact: an unauthenticated remote attacker can trigger a read overrun of up to
52 bytes, possibly causing the process to terminate. According to the upstream
commit message, exfiltration of the bytes read does not appear possible.

## Fix

Apply the [upstream patch](https://github.com/krb5/krb5/commit/2e75f0d9362fb979f5fc92829431a590a130929f)
or update to a version containing the fix.

## Proof of Concept

The following video demonstrates the issues in a Dockerized krb5 lab
environment compiled with AddressSanitizer (ASan), showing memory-safety
failures triggered over the network:

In the PoC video, the service is supervised so that a child listener is started
again after the server crashes.

[![](https://img.youtube.com/vi/zpBrriAJxCQ/0.jpg)](https://www.youtube.com/watch?v=zpBrriAJxCQ)

## Credit

Reported by Cem Onat Karagun.

---
title: "Advisory - Kerberos (krb5) Two Unauthenticated Network Vulnerabilities: CVE-2026-40355 & CVE-2026-40356"
layout: post
---

## Summary

I reported two vulnerabilities in [MIT Kerberos (krb5)](https://kerberos.org/about/FAQ.html). Both are pre-authentication issues and can be triggered remotely.

The issues were fixed upstream in [commit `2e75f0d`](https://github.com/krb5/krb5/commit/2e75f0d9362fb979f5fc92829431a590a130929f).

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

Apply the [upstream patch](https://github.com/krb5/krb5/commit/2e75f0d9362fb979f5fc92829431a590a130929f) or update to a version containing the fix:

## Proof of Concept

The following video demonstrates the issues in a Dockerized krb5 lab
environment compiled with AddressSanitizer (ASan), showing memory-safety
failures triggered over the network:

In the PoC video, the service is supervised so that a child listener is started
again after the server crashes.

[![](https://img.youtube.com/vi/zpBrriAJxCQ/0.jpg)](https://www.youtube.com/watch?v=zpBrriAJxCQ)

## Credit

Reported by Cem Onat Karagun.

---
title: "macOS Vulnerability Disclosure: Four Issues I Reported to Apple - CVE-2026-43773 & CVE-2026-43806"
layout: post
date: 2026-07-27 22:34:00 +0200
---

In macOS Tahoe 26.6, Apple addressed four security issues I had previously
reported. The [HFS+](https://theapplewiki.com/wiki/IOS_5_HFS_Heap_Buffer_Overflow)
issue was assigned CVE-2026-43773. Two
[mDNSResponder](https://www.reddit.com/r/explainlikeimfive/comments/1bk3g5d/comment/kvvjn77/)
reports were closed under CVE-2026-43806, and Apple also resolved an issue
affecting [xar](https://en.wikipedia.org/wiki/Xar_(archiver)).

The reports demonstrated reproducible security impact. Apple awarded bounties
for the HFS+ report and the mDNSResponder out-of-bounds-read report; both were
addressed in macOS Tahoe 26.6.

## Issues Addressed

### CVE-2026-43773 — HFS+

#### Impact

Apple addressed a kernel heap-buffer-overflow in HFS+ with an arbitrary
disk-write primitive, assigned CVE-2026-43773. A crafted USB disk image can
trigger an out-of-bounds kernel read. My report also documented a disk-write
primitive.

#### Proof of Concept

The following video demonstrates the PoC by inserting a crafted HFS+ USB disk
into an affected Mac in a controlled environment:

[![CVE-2026-43773 PoC video](https://img.youtube.com/vi/NSw_WHOT8d8/hqdefault.jpg)](https://www.youtube.com/watch?v=NSw_WHOT8d8)

Watch the PoC on YouTube: [https://www.youtube.com/watch?v=NSw_WHOT8d8](https://www.youtube.com/watch?v=NSw_WHOT8d8)

### CVE-2026-43806 — mDNSResponder

Apple closed two mDNSResponder reports under CVE-2026-43806:

- An out-of-bounds read leaking stale bytes and unicast-mDNS transaction IDs.
- An out-of-bounds write allowing local corruption of global state.

Apple awarded a bounty for the out-of-bounds-read report.

### xar Acknowledgment

Apple also resolved a vulnerability affecting xar in the same release.

## Related Apple Acknowledgment

Earlier in 2026, Apple also acknowledged my PPP out-of-bounds-read report in
[macOS Tahoe 26.5](https://support.apple.com/en-us/127115#:~:text=Cem%20Onat%20Karagun), released May 11, 2026.

## Closing Notes

The Apple Security Bounty awards covered my AI subscriptions and the
second-hand MacBook I recently bought for this research. Further technical
details may be published in future.

## References

- [Apple Security Release Notes](https://support.apple.com/en-us/128067)
- [SANS Internet Storm Center: Apple Patches Everything, July 2026](https://isc.sans.edu/diary/Apple+Patches+Everything+July+2026/33196)
- [ZDI: The July 2026 Apple Security Update Review](https://web.archive.org/web/20260730161445/https://www.zerodayinitiative.com/blog/2026/7/29/the-july-2026-apple-security-update-review)
- [mDNSResponder CVE collision write-up by another researcher from Sophos Japan](https://skypoc.wordpress.com/2026/08/01/cve-2026-43806/)
- [My security research acknowledgments](/about/)

---
title: "Capturing an Apple Target Flag in XNU - Kernel Register Control"
description: "An HFS+ attribute B-tree overflow placed a boot-specific Apple Target Flag into an XNU register, proving kernel register control on macOS."
layout: post
date: 2026-08-03 21:00:00 +0200
---

In July, Apple fixed [four issues I reported in macOS Tahoe
26.6](https://cems.fun/2026/07/27/apple-security-update-four-issues.html): two
assigned CVEs, two paid. This is my fifth report to Apple. I
proved more with it than with any of the four and got nothing for it.

## Target Flags

Apple introduced Target Flags in October 2025. They turn the usual argument
about whether a memory-safety bug is exploitable into something you prove on the
device instead.

Your running iPhone or Mac picks a handful of random values at every boot —
[Target Flags](https://security.apple.com/bounty/target-flags/) — and publishes
them in the commpage, at fixed addresses any process can read. There is a flag
for reading kernel memory, a flag for controlling a kernel register, and so on.
Reading the value proves nothing; the flag is captured when you make the kernel
itself hold it. You produce that instead of describing what your bug might be
able to do.
Apple's [bounty categories](https://security.apple.com/bounty/categories/) then
price the result:

![Apple Security Bounty — kernel Target Flag categories]({{site.url}}/assets/hfs-target-flag/1.png)

I captured the second one on the latest public release of macOS at the time,
running on an M-series processor.

## The Missing HFS+ Length Check

`hfs_swap_BTNode` byte-swaps B-tree keys read from an
[HFS+](https://en.wikipedia.org/wiki/HFS_Plus) volume. It branches on which tree
the key came from, and the two branches do not validate the key the same way.

```
catalog   : sub w13, w3, #0x205    ; keyLength - 517
            cmp w12, w13, uxth
            b.hs <reject>          ; two-sided bound, folded into one compare

attribute : cmp w2, w16, uxth      ; minimum length vs keyLength
            b.hi <reject>          ; lower bound only
```

The attribute branch only checks the minimum length; nothing checks it against
the documented maximum. That maximum is 266 bytes, and a key on disk claiming
4094 is accepted.

## What Happens Next

That length is then reused as a copy size. Two bytes are added for the length
field itself, and the record-iteration primitive copies the result into the
iterator's fixed key buffer:

```
ldrh  w8, [x24]        ; keyLength, straight from disk = 4094
add   x2, x8, #2       ; size = 4096
add   x0, x19, #0x1c   ; destination = &iterator->key
bl    <block copy>
```

The destination is 522 bytes, inside a 552-byte structure that lands in the
768-byte kernel allocation class. The copy overruns the key buffer by roughly
3.5 KB, through the rest of the allocation and on into whatever the kernel put
next to it. Every byte of that comes verbatim from the disk image.

Reaching it needs no privileges: mount the image, then run `xattr -l` on one
file.

## Building the Target Flag Proof

The flag value is random per boot, so the proof has to be built after booting:

1. Boot. The kernel re-randomises its flags.
2. Read this boot's kernel register-control flag and record it.
3. Author an image whose overflow payload is that value repeated, and no copy of
   any other flag.
4. Mount it. Run one `xattr -l`.
5. Confirm the panic's saved registers hold it, and that it matches the value
   recorded in step 2 on the same boot.

## Target Flag in Register

One `hdiutil attach`. One `xattr -l` at 19:35:03. The kernel panicked at
19:35:16 by its own clock:

```
Calendar: 0x6a29a054 0x000123ab   # panic wall clock = 19:35:16 +0200
x10:      0x08acf5210b466b05      # == this boot's kernel register-control flag
```

No spray, no loop, no repetition.

## Independent Discovery

[Feng Xue (@s0what)](https://x.com/s0what/status/2082133089120370963) published
the same bug in July and was told what I was told. Our panics match:

```
panic(cpu 6 caller 0xfffffe004eeba264): Kernel data abort. at pc 0xfffffe004e564c4c
Panicked task 0xfffffe250fd2dcd0: 74 pages, 1 threads: pid 23744: xattr
com.apple.filesystems.hfs.kext(715.120.4)[49929E1E-F6AF-30B5-BD33-22966DCF0D52]

x8:  0xbf60e7fa45741446   x9:  0xbf60e7fa45741446
x10: 0xbf60e7fa45741446   x11: 0xbf60e7fa45741446   <- planted payload
x12: 0x0000001600000ffe                             <- fileID 22, keyLength 4094
x13: 0x0063002800000000                             <- attrNameLen 40, first char 'c'
x14: 0x0061002e006d006f                             <- UTF-16 "om.a"
x15: 0x0065006c00700070                             <- UTF-16 "pple"
```

His registers hold the same fields: `x8`–`x11` full of `0x41`,
`x12 = 0x0000001200000fa0` for file ID 18 and length 4000, `x13`–`x15` spelling
`com.test.vuln`.

In the replies to that thread, P. M. says this same bug earned them one of their
$20,000 bounties as a Target Flag capture, reported on March 8.

<blockquote class="twitter-tweet" data-dnt="true" data-conversation="none"><a href="https://twitter.com/slinafirinne/status/2082282513167270036"></a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## Timeline

I reported this bug ~13 days late. It is not eligible for credit in a security
advisory or for a bounty. The fix is in the public macOS 26.6.

I found it alongside the rest of my HFS work and held it back on purpose. That
first group came out of fuzz testing (a different approach I may write about
separately), and this one looked like it could be pushed past a crash, so I kept
it while I worked toward either a Target Flag proof or a larger chain combining
several findings. Apple fixed it on May 28. I was still escalating.

**Apple's advice afterwards was to test against the latest beta before
submitting, not the latest release.**

What I would do differently is file the bug as soon as it reproduces and send
the Target Flag work as a follow-up, which is what I ended up doing anyway, only
too late for it to count.

My last reply to Apple Product Security was short:

![My reply to Apple Product Security: "thanks, my time will come."]({{site.url}}/assets/hfs-target-flag/2.png)

## References

- [Feng Xue (@s0what)](https://x.com/s0what/status/2082133089120370963) — published the same HFS+ attribute B-tree overflow independently.
- [P. M. (@slinafirinne)](https://x.com/slinafirinne/status/2082282513167270036) — reported it first, on March 8, as a Target Flag capture.
- [Apple Security Bounty: Target Flags](https://security.apple.com/bounty/target-flags/)
- [Apple Security Bounty: Categories](https://security.apple.com/bounty/categories/)
- [About the security content of macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [My earlier disclosure post: four issues, two CVEs, two bounties](https://cems.fun/2026/07/27/apple-security-update-four-issues.html)
- [My security research acknowledgments](/about/)

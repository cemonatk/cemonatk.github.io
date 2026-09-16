---
title: "Capturing an Apple Target Flag in XNU - Part 2: Internal Duplicate"
description: "I captured Apple's kernel Target Flag with an APFS vulnerability on the newest beta. Apple fixed and credited the issue, then closed my report as an internal duplicate."
layout: post
date: 2026-09-16 13:00:00 +0200
---

Previous in this series: [Capturing an Apple Target Flag in XNU - Part 1: Fixed in Beta](/2026/08/03/apple-target-flag-register-control.html)

Bug bounty programs give independent researchers a way to report
vulnerabilities privately and receive a reward for eligible work. That gives a
vendor time to fix a bug before its details or a working exploit spread.
Exploit brokers and surveillance vendors also pay for bugs used in attack
chains.

Amnesty's Pegasus Project reported evidence that family members of Saudi
journalist [Jamal
Khashoggi](https://en.wikipedia.org/wiki/Jamal_Khashoggi) were [targeted before
and after his 2018
murder](https://web.archive.org/web/20240107175931/https://securitylab.amnesty.org/latest/2021/07/the-pegasus-project/).

When Apple [redesigned its bounty program in
2025](https://web.archive.org/web/20251012210403/https://security.apple.com/blog/apple-security-bounty-evolved),
it framed the changes around the same threat:

> "Mercenary spyware attacks typically chain many vulnerabilities together,
> cross different security boundaries, and incrementally escalate privileges."

#### What Is a Target Flag?

Each supported Apple device generates test values called Target Flags, and
capturing one through a real vulnerability helps prove that the bug is
exploitable and could be combined with other bugs in an attack chain.
I explained this in a little more detail in [Part
1](/2026/08/03/apple-target-flag-register-control.html).

Apple raised its top reward to **$2 million**, with bonuses that can push the
maximum beyond **$5 million**, and introduced [Target
Flags](https://security.apple.com/bounty/target-flags/) as objective proof for
faster award decisions.

<img src="/assets/apfs-target-flag/kernel-target-flag-categories-half.png" alt="Apple Security Bounty kernel Target Flag categories" width="50%">

I later captured another kernel Target Flag with an APFS bug that was assigned
[CVE-2026-84523](https://support.apple.com/en-us/149034#:~:text=CVE%2D2026%2D84523).
This time I followed Apple's advice: I tested the newest beta and submitted the
complete report with the flag.

<p style="font-size: 1.1em; font-weight: 600;">Apple gave no indication of a duplicate before the September 14 updates.</p>

Apple's public advisory credits me and an anonymous researcher.

<a href="https://support.apple.com/en-us/149035#:~:text=CVE%2D2026%2D84523%3A%20Cem%20Onat%20Karagun%2C%20an%20anonymous%20researcher"><img src="/assets/apple-2026/apfs-cve-2026-84523-apple-credit.png" alt="Apple APFS advisory credit for CVE-2026-84523" width="70%"></a>

Apple later marked it as a duplicate of an issue it had found **"internally"**.

<img src="/assets/apfs-target-flag/internal-duplicate-fix-available.jpg" alt="Apple Security Research report showing an internal duplicate and an available fix" width="54%">

## What Apple Published

As of this post, Apple's public [bounty
guidelines](https://security.apple.com/bounty/guidelines/) say:

> "Only the first complete and actionable report we receive for an issue is
> eligible for a reward."

Apple's [Target Flags](https://security.apple.com/bounty/target-flags/) page
says:

> "the specific flag that you capture confirms the level of exploitability you
> achieved"

This is the part I think is unfair: I could not find anything in Apple's
published guidelines or terms saying that an internal finding can close an
outside report as a duplicate. I had not seen this reported publicly before
similar notices appeared across many accounts on September 15, 2026.

## My mDNSResponder Reports

The same batch affected my two mDNSResponder reports. They shared one root
cause but had different effects. Apple fixed and credited both under
CVE-2026-43806, as described in [an earlier
post](/2026/07/27/apple-security-update-four-issues.html).

The portal first marked the read report as **bounty-awarded, then changed it to
a duplicate before I received payment**. The write report is marked resolved and
lists me as the first reporter. Since both came from the same root cause, I
hope Apple will review this decision.

## Researchers Losing Trust

Some researchers said they were done reporting to Apple. @frostcrunch18 said
the same treatment had affected many reports and that pending bounties and
credits had been reversed.

<blockquote class="twitter-tweet" data-dnt="true"><a href="https://twitter.com/frostcrunch18/status/2100158445047423459">Post by @frostcrunch18 about leaving Apple's program</a></blockquote>

<blockquote class="twitter-tweet" data-dnt="true"><a href="https://twitter.com/gergely_kalman/status/2100001682654728316">Post by Gergely Kalman (@gergely_kalman)</a></blockquote>

<blockquote class="twitter-tweet" data-dnt="true"><a href="https://twitter.com/frappehv/status/2100030779057168503">Post by @frappehv about a report reclassified as an internal duplicate</a></blockquote>

<blockquote class="twitter-tweet" data-dnt="true"><a href="https://twitter.com/thedawgyg/status/2100196854256263430">Post by @thedawgyg about an internal duplicate decision</a></blockquote>

<blockquote class="twitter-tweet" data-dnt="true"><a href="https://twitter.com/avokadopwn/status/2100186551619559847">Post by @avokadopwn about the incentive this creates</a></blockquote>

<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## Final Note

Duplicates happen in every program, but leaving reports open for months or
years before marking them as "internal duplicates" is not sustainable; I hope
Apple hears the researchers speaking out on X and acts before more leave the
program.

I will not publish technical details unless someone else has already made them
public or users have had enough time to update.

## References

- [Apple Security Bounty Target Flags](https://security.apple.com/bounty/target-flags/)
- [Apple Security Bounty Guidelines](https://security.apple.com/bounty/guidelines/)
- [Apple Security Bounty Terms and Conditions](https://security.apple.com/terms-and-conditions/)
- [Archived Apple announcement introducing Target Flags](https://web.archive.org/web/20251012210403/https://security.apple.com/blog/apple-security-bounty-evolved)
- [Archived Amnesty Pegasus Project report](https://web.archive.org/web/20240107175931/https://securitylab.amnesty.org/latest/2021/07/the-pegasus-project/)
- [Apple advisory for CVE-2026-84523](https://support.apple.com/en-us/149034#:~:text=CVE%2D2026%2D84523)

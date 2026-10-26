---
title: "Vim Vulnerability Disclosure: 6 Memory Safety CVEs I Reported"
layout: post
date: 2021-12-01 12:00:00 +0100
---

In late 2021, six vulnerabilities I reported in Vim were assigned CVEs.

4 were classified as heap-based buffer overflows, 1 as use of an
uninitialized variable, and 1 as a use-after-free. Vim fixed the issues in
patches released between October 25 and November 19. The final CVE record,
CVE-2021-3984, was published on December 1, 2021.

[![CVE-2021-3984 marked valid on Huntr](/assets/vim-2021/cve-2021-3984-huntr-report.png)](https://web.archive.org/web/20211201075906/https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a/)

The issues affected several parts of the editor, including scrolling, line
handling, spell suggestions, window commands, regular-expression processing,
and C indentation.

Vim maintainer Bram Moolenaar authored all six upstream fixes.

I submitted all 6 reports through the [Huntr platform](https://huntr.com/bounties/b114b5a2-18e2-49f0-b350-15994d71426a).

<a href="https://huntr.com/bounties/b114b5a2-18e2-49f0-b350-15994d71426a"><img src="/assets/vim-2021/cve-2021-3984-huntr-status.png" alt="Huntr status for CVE-2021-3984 showing the report as fixed, with Cem as the finder and Bram Moolenaar as the fixer" style="width: 55%; height: auto;"></a>

## Vulnerabilities

The issues are listed below in the order their Vim patches were released.

1. [CVE-2021-3903](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim/CVE-2021-3903.md) ([Huntr](https://web.archive.org/web/20211027152732/https://huntr.dev/bounties/35738a4f-55ce-446c-b836-2fb0b39625f8/)) - Heap-based buffer overflow. Reported October 25 and fixed in [Vim 8.2.3564](https://github.com/vim/vim/commit/777e7c21b7627be80961848ac560cb0a9978ff43) the same day.
2. [CVE-2021-3927](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim/CVE-2021-3927.md) ([Huntr](https://web.archive.org/web/20211107084702/https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0/)) - Heap-based buffer overflow. Reported October 26 and fixed in [Vim 8.2.3581](https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e) on November 4.
3. [CVE-2021-3928](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim/CVE-2021-3928.md) ([Huntr](https://web.archive.org/web/20211105101433/https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd/)) - Use of an uninitialized variable. Reported October 29 and fixed in [Vim 8.2.3582](https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732) on November 4.
4. [CVE-2021-3973](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim/CVE-2021-3973.md) ([Huntr](https://web.archive.org/web/20211129191547/https://huntr.dev/bounties/ce6e8609-77c6-4e17-b9fc-a2e5abed052e/)) - Heap-based buffer overflow. Reported November 12 and fixed in [Vim 8.2.3611](https://github.com/vim/vim/commit/615ddd5342b50a6878a907062aa471740bd9a847) on November 17.
5. [CVE-2021-3974](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim/CVE-2021-3974.md) ([Huntr](https://web.archive.org/web/20211128142447/https://huntr.dev/bounties/e402cb2c-8ec4-4828-a692-c95f8e0de6d4/)) - Use-after-free. Reported October 25 and fixed in [Vim 8.2.3612](https://github.com/vim/vim/commit/64066b9acd9f8cffdf4840f797748f938a13f2d6) on November 17.
6. [CVE-2021-3984](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim/CVE-2021-3984.md) ([Huntr](https://web.archive.org/web/20211201075906/https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a/)) - Heap-based buffer overflow. Reported November 18 and fixed in [Vim 8.2.3625](https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655) on November 19.

The linked GitHub pages preserve my original reports, including the minimized
proofs of concept, reproduction steps, and sanitizer output.

[![Bram Moolenaar confirming the CVE-2021-3984 fix](/assets/vim-2021/cve-2021-3984-huntr-validation.png)](https://web.archive.org/web/20211201075906/https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a/)

## In Memory of Bram Moolenaar

[Bram Moolenaar](https://en.wikipedia.org/wiki/Bram_Moolenaar) (1961-2023)
made Vim part of everyday life for generations of developers. Rest in peace.

The CVEs above also offered a less conventional way to exit Vim.

## References

- [My onefuzzyway repository](https://github.com/cemonatk/onefuzzyway)
- [My Vim CVE reports on GitHub](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/vim)
- [Archived Huntr report for CVE-2021-3984](https://web.archive.org/web/20211201075906/https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a/)
- [My security research acknowledgments](/about/)

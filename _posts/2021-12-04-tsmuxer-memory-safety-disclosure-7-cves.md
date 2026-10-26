---
title: "tsMuxer Vulnerability Disclosure: 7 Memory Safety CVEs I Reported"
layout: post
date: 2021-12-04 01:30:00 +0100
---

In May 2021, I reported 7 vulnerabilities in tsMuxer. 5 were
heap-based buffer overflows, 1 was an out-of-bounds read, and 1 was a
divide-by-zero issue. Each report included a proof-of-concept file and
sanitizer output. Some also included root-cause analysis, including [my
analysis and fix for
CVE-2021-34070](#root-cause-and-fix-for-cve-2021-34070).

tsMuxer is a C++ transport-stream muxer. It was also used by [Universal Media
Server](https://www.universalmediaserver.com/about/#:~:text=%2C%20MEncoder%2C-,tsMuxeR,-%2C%20AviSynth%2C%20VLC%20and)
([archived page](https://web.archive.org/web/20211119203917/https://www.universalmediaserver.com/about/#:~:text=%2C%20MEncoder%2C-,tsMuxeR,-%2C%20AviSynth%2C%20VLC%20and)).

The project merged fixes for all seven reports on June 9, 2021. The first five
CVEs were published on June 23. CVE-2021-35344 and CVE-2021-35346, the final
two records, were published on December 3, 2021.

## Vulnerabilities

The issues are listed in the order I reported them.

1. [CVE-2021-34071](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-34071.md) - Heap-based buffer overflow. Reported in [issue #423](https://github.com/justdan96/tsMuxer/issues/423) on May 22 and fixed by [commit `ea879f3b`](https://github.com/justdan96/tsMuxer/commit/ea879f3b915baa4f9d145ce44229f7b3b1952c30).
2. [CVE-2021-34067](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-34067.md) - Heap-based buffer overflow. Reported in [issue #424](https://github.com/justdan96/tsMuxer/issues/424) on May 22 and fixed by [commit `d77ed5e8`](https://github.com/justdan96/tsMuxer/commit/d77ed5e8dc701f64ed5da317b896879e621de865).
3. [CVE-2021-34070](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-34070.md) - Out-of-bounds read. Reported in [issue #426](https://github.com/justdan96/tsMuxer/issues/426) on May 24 and fixed by [commit `378377e9`](https://github.com/justdan96/tsMuxer/commit/378377e9245549caf889988ca6c21807ec7f8873).
4. [CVE-2021-34068](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-34068.md) - Heap-based buffer overflow. Reported in [issue #427](https://github.com/justdan96/tsMuxer/issues/427) on May 24 and fixed by [commit `ea879f3b`](https://github.com/justdan96/tsMuxer/commit/ea879f3b915baa4f9d145ce44229f7b3b1952c30).
5. [CVE-2021-34069](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-34069.md) - Divide-by-zero. Reported in [issue #428](https://github.com/justdan96/tsMuxer/issues/428) on May 24 and fixed by [commit `9070a991`](https://github.com/justdan96/tsMuxer/commit/9070a9917f45bcada64a16be3b280d5147f9074d).
6. [CVE-2021-35344](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-35344.md) - Heap-based buffer overflow. Reported in [issue #432](https://github.com/justdan96/tsMuxer/issues/432) on May 27 and fixed by [commit `8028fb84`](https://github.com/justdan96/tsMuxer/commit/8028fb8449f6f1c702b7f70369c889e8633378a8).
7. [CVE-2021-35346](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer/CVE-2021-35346.md) - Heap-based buffer overflow. Reported in [issue #436](https://github.com/justdan96/tsMuxer/issues/436) on May 27 and fixed by [commit `d77ed5e8`](https://github.com/justdan96/tsMuxer/commit/d77ed5e8dc701f64ed5da317b896879e621de865).

## Root Cause and Fix for CVE-2021-34070

For CVE-2021-34070, I went beyond the sanitizer crash and traced the root
cause in the VC-1 parser. An attacker-controlled value could select index 7
from a table that contained only five entries. I provided a proof-of-concept
fix that added the missing bounds checks.

[![Root-cause analysis and proposed fix for CVE-2021-34070](/assets/tsmuxer-2021/cve-2021-34070-root-cause-and-fix.png)](https://github.com/justdan96/tsMuxer/issues/426)

The maintainer noted that this code originated in FFmpeg and said he would
push the fix. The [merged patch](https://github.com/justdan96/tsMuxer/pull/429/files)
used the bounds-checking direction from my report while also restoring the two
missing frame-rate values from the FFmpeg table.

[![tsMuxer maintainer response to the CVE-2021-34070 report](/assets/tsmuxer-2021/cve-2021-34070-maintainer-comments.png)](https://github.com/justdan96/tsMuxer/issues/426#issuecomment-847323598)

## References

- [My tsMuxer CVE reports on GitHub](https://github.com/cemonatk/onefuzzyway/tree/main/CVEs/tsMuxer)
- [CVE-2021-34070 report and fix recommendation](https://github.com/justdan96/tsMuxer/issues/426)
- [CVE-2021-34070 merged fix](https://github.com/justdan96/tsMuxer/pull/429/files)
- [Universal Media Server About page](https://www.universalmediaserver.com/about/#:~:text=%2C%20MEncoder%2C-,tsMuxeR,-%2C%20AviSynth%2C%20VLC%20and)
- [Archived Universal Media Server About page](https://web.archive.org/web/20211119203917/https://www.universalmediaserver.com/about/#:~:text=%2C%20MEncoder%2C-,tsMuxeR,-%2C%20AviSynth%2C%20VLC%20and)
- [My security research acknowledgments](/about/)

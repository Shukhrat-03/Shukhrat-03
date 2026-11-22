## Shukhratbek Uraiimov

Security researcher focused on memory-safety bugs in C/C++ parsers for industrial and embedded protocols
(Modbus, S7, TLS, USB). I find them, build a reproducible PoC under ASan/guard pages, report them
privately, and publish details only after the maintainer or the CNA has shipped or acknowledged the fix.

### Published CVEs

Every row below is a published record. The CVE.org link is the source of truth, including the credit line.

| CVE | Project | Bug | CWE | CVSS | Credit |
|---|---|---|---|---|---|
| [CVE-2026-71254](https://www.cve.org/CVERecord?id=CVE-2026-71254) | [nanoMODBUS](https://github.com/debevv/nanoMODBUS) | Server OOB write in `handle_read_file_record()` | 787 | 9.8 | finder |
| [CVE-2026-71255](https://www.cve.org/CVERecord?id=CVE-2026-71255) | nanoMODBUS | Client OOB write via `object_length` in `recv_read_device_identification_res()` | 787 | 8.6 | finder |
| [CVE-2026-71256](https://www.cve.org/CVERecord?id=CVE-2026-71256) | nanoMODBUS | Client OOB read leading to wild-pointer write via `object_id` | 125 | 9.8 | finder |
| [CVE-2026-11404](https://www.cve.org/CVERecord?id=CVE-2026-11404) | [Cesanta Mongoose](https://github.com/cesanta/mongoose) | OOB read in built-in TLS ClientHello session-id parsing ([advisory](https://www.vulncheck.com/advisories/cesanta-mongoose-out-of-bounds-read-in-mg-tls-builtin-clienthello-session-id-parsing)) | 125 | 7.5 | finder |
| [CVE-2026-11826](https://www.cve.org/CVERecord?id=CVE-2026-11826) | [OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3) | Heap overflow in Modbus master `getData()` ([fix](https://github.com/thiagoralves/OpenPLC_v3/commit/b4702061dc14d1024856f71b4543298d77007b88), [write-up](https://gist.github.com/Shukhrat-03/5cf1825b72e485ef98a32958dfbc611a)) | 122 | 8.8 | finder |
| [CVE-2026-111280](https://www.cve.org/CVERecord?id=CVE-2026-111280) | [snap7](https://github.com/davenardella/snap7) | OOB write in `TSnap7MicroClient::opReadArea` ([issue](https://github.com/davenardella/snap7/issues/31)) | 787 | 7.4 | finder, co-credited with Mayur Agnihotri |
| [CVE-2026-131848](https://www.cve.org/CVERecord?id=CVE-2026-131848) | snap7 | OOB write in `opReadMultiVars` ([issue](https://github.com/davenardella/snap7/issues/32)) | 787 | 7.4 | finder, co-credited with Mayur Agnihotri |
| [CVE-2026-131849](https://www.cve.org/CVERecord?id=CVE-2026-131849) | snap7 | Heap overflow in `opReadSZL` ([issue](https://github.com/davenardella/snap7/issues/11)) | 122 | 7.4 | finder, co-credited with Andreas Waidler (reported first) |
| [CVE-2026-61495](https://www.cve.org/CVERecord?id=CVE-2026-61495) | [TinyUSB](https://github.com/hathach/tinyusb) | OOB write in `mtp_container_get_string()` ([fix](https://github.com/hathach/tinyusb/commit/e85c2b8affa1efbf00d398d59e7a87d3e61cc4a9)) | 787 | 6.8 | finder |
| [CVE-2026-61497](https://www.cve.org/CVERecord?id=CVE-2026-61497) | TinyUSB | Integer underflow in HID report descriptor parser ([fix](https://github.com/hathach/tinyusb/commit/85047e1777f5c20b7a936aa905c746125d3ed066), [write-up](https://gist.github.com/Shukhrat-03/8fe6e5881614a7f86b5d2b87d44ea706)) | 191 | 5.2 | reporter |

CNAs: TuranSec (nanoMODBUS) and VulnCheck (the rest).

### Where these projects run

Modbus and S7 clients and servers, PLC runtimes, embedded HTTP/TLS stacks and USB device stacks. A memory-safety
bug in these parsers is reachable from the network or from a USB cable, which is why I look there.

### Upstream fixes

Patches I send to the affected projects are listed here as they are opened.

<!-- PR list: filled in after the pull requests are opened -->

### Method

C/C++ decode paths, length fields trusted before the bounds check, PoCs that crash a stock build deterministically
(ASan, or a `PROT_NONE` guard page where the ASan runtime is unavailable). Disclosure through the CNA or the
project's private advisory channel first.

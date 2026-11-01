# CookUp / GooPDF: server-gated installer cluster and related applications

**Research snapshot:** 2026-11-01  
**Scope:** CookUp, GooPDF, Velum, and related cooking/PDF-themed installer indicators  
**Assessment:** **High confidence** that the investigated CookUp and GooPDF loaders share a distinctive downloader/decoder implementation; **medium-to-high confidence** that the wider applications are associated through an installer/distribution ecosystem. **Not** an assertion that all listed files execute the same payload or are controlled by the same actor.

> **Important:** The observed CookUp recipe application did not itself establish malicious behavior. The associated installer implements remote-fetch/native-loading capabilities. During testing, live infrastructure did not provide a verified second-stage payload. These are suspicious, server-gated installers; avoid describing every listed binary as confirmed malware.

## Executive summary

CookUp (`Cookup-Setup.exe`) is a 32-bit Go installer that contacts `applicensingstudio.com` and implements a conditional remote-fetch path with custom decoding and native PE-loading capabilities. GooPDF (`GooPDF.Setup.exe`) independently showed a closely matching staged request design and decoder. Code-level comparison of the custom decoder passed **134 comparison vectors**, and a **22,688-byte CookUp decoder dump** matched the compared logic in the previous investigation. That is substantially stronger evidence than shared branding alone.

The wider cluster includes PantryLane, RecipeRover, NomadicCookNow, PeregrineCook, Foodzi, MyPdfSoftware, Paperly, Velum and other installers. Many submitted samples carry similarly shaped preparation URLs, often with a final `init=prep` parameter, under multiple reported publisher names. At this stage, those entries should be treated as **related hunting leads**, not as proven identical loaders.

## Relationship / confidence matrix

| Relationship or observation | Confidence | Evidence / limitation |
|---|---|---|
| CookUp ↔ GooPDF, shared staged-fetch and decoder design | **High** | `init=prep` / `init=fin`, response gating, aligned decoder behavior including 134 comparison vectors; no authentic second-stage delivery captured |
| CookUp/GooPDF ↔ Velum | **Medium** | Related preparation-URL conventions; prior static comparison suggested UID-generation overlap (environment mask / token nibbles / `GetTickCount() XOR PID`); implementation identity and operator attribution remain unproven |
| PantryLane ↔ PantryLane | **High** | Two extracted installer executables include `PantryLane.Setup.dll` v1.5.2.7, share the .NET 8 bundled runtime and PE layout; generic bundled runtime similarity is not proof of shared proprietary code |
| PantryLane / RecipeRover / NomadicCookNow / PeregrineCook / Foodzi ↔ broader cluster | **Medium-to-high, distribution association** | Repeated parameter families, `init=prep`, cooking-themed installer ecosystem, reported publisher overlap; execution behavior not individually confirmed |
| All 44 hashes belong to one malicious payload family | **Not established** | Hash collection documents association, not a single payload or common actor |

## Server-gated fetch: what was actually observed

1. The installer constructs a preparation URL and requests `init=prep` from a remote service.
2. In the analyzed CookUp/GooPDF flow, the client expects a **32-character ASCII token** to continue certain branches. Local sinkhole experiments explored token validation and a digit-parity-dependent branch. This was **local branch testing**, not an authentic server authorization.
3. A later `init=fin` stage can fetch a remote blob, with a **four-byte length-framed** payload-handling path and a custom decoder (research notes associate the decoder with the constant `0x95000000`).
4. The loader has memory/native-PE-loading capability; this **does not establish that a malicious stage was delivered or executed** in the observed live sessions.
5. Actual infrastructure gave HTTP 200 with empty bodies in observed follow-up tests; no authentic active second-stage body was recovered. A synthetic sinkhole response can demonstrate reachable code paths, **not** prove live delivery.

**Example 32-character prep token captured during GooPDF analysis:** `3C6BB422B9F3D250C94AAB1342B8E468` (example response value; do not use as a universal signature).

## URI structure: three useful cluster patterns

**Template A — version/channel/language/architecture/build:**

```text
https://<host>/?ver=<hex>&chan=<hex>&lang=<hex>&arch=<hex>&build=<hex>&init=prep
```

Observed examples: `applicensingstudio.com` (CookUp), `setuppdfsoft.com` (GooPDF), `appsetupstore.com` (Pantry), `peregrinecooksoft.com` (Foodzi).

**Template B — application/revision IDs:**

```text
https://<host>/?appid=<8-hex>&revid=<8-hex>&init=prep
```

Observed examples: `cookingsuiteinstaller.com` (PantryLane), `nomadiccooknow.com`, `nomadiccookapp.com`, `mypdfsoftware.com`.

**Template C — version/API ID:**

```text
https://<host>/?ver=<8-hex>&apiid=<8-hex>&init=prep
```

Observed examples: `reciperoverapp.com`, `webpdfinstallerstudio.com` (Paperly).

**Additional lead:** `securedocinstaller.com/?ver=...&appid=...&init=prep` associated with Velum; this mixes fields and should not be conflated with the templates above.

**Analyst note:** URI template similarity is a strong *clustering lead*, especially in conjunction with the reported publishers and application themes. `init=prep` alone is not a sufficiently unique malware signature. Domains and URLs are **observed indicators**, not verified command-and-control for every sample.

## Quick analysis methods

- **Static triage:** compute SHA-256; identify PE architecture, timestamps, resources, sections, overlay, embedded .NET assemblies, and signer information. Check Authenticode validity separately from version-resource publisher names.
- **.NET review:** unpack/self-extract bundled assemblies when possible; inspect with dnSpy/ILSpy, compare methods and string/URL construction. For Go, locate network/decoder/native-load routines in Ghidra or similar tooling.
- **Network capture:** instrument DNS, HTTPS and process creation in an isolated lab (Fiddler/Wireshark/ProcMon); record complete URI and responses. Separate *observed on the wire* from *embedded statically*.
- **Controlled branch tests:** redirect only in the isolated VM to a local sinkhole; test empty responses and synthetically generated 32-character prep tokens. Mark the resulting behavior as *laboratory-induced*.
- **Runtime instrumentation:** trace Winsock/Schannel and process/memory APIs with Frida or an equivalent debugger; preserve payload bytes if they are ever actually received. Avoid claiming exfiltration, persistence or stage execution without direct evidence.
- **Hunt and compare:** use `FetchRemoteBlob` only as a broad retrohunt pivot (not a family-defining YARA atom); prioritize a verified code-level comparison of proprietary routines over repeated .NET runtime strings.

## IOCs

The accompanying [`tamperedchef2026-iocs.csv`](tamperedchef2026-iocs.csv) contains **44 unique SHA-256s**, **18 distinct filenames**, and three **reported** signer/publisher strings (24 `Launch Window, LLC`; 19 `Net Sourcing Experts LLC`; 1 `Pausatech LLC`). Some URLs were recovered from sample/configuration context; blank URL fields mean *not recorded*, not *no network activity*. The CSV's `Signature` column should be understood as *reported identity*, **not individually verified valid Authenticode signatures**.

### Core investigated sample hashes

| Sample | SHA-256 |
|---|---|
| CookUp | `e7bc65daf98767646cb1a0e8c3d19cf0db0dce4618a9bcd2d287426cfd2c9034` |
| GooPDF | `af74f8974df1bff1c938a6f8f585cc8b5f370c98d41e7c5f476a4abda3cbfa2e` |
| PantryLane variant 1 | `9a28034e6f57a5dc440c3271134f0557a752819cacdf5503b22a42835d2db995` |
| PantryLane variant 2 | `01fdb4146e3a5d32baf349063835b106498b341f589522dd5251cf7d9ae327d0` |

### Domains in submitted URL observations (not exhaustive DNS intelligence)

`applicensingstudio.com`, `setuppdfsoft.com`, `cookingsuiteinstaller.com`, `appsetupstore.com`, `reciperoverapp.com`, `nomadiccooknow.com`, `nomadiccookapp.com`, `peregrinecooksoft.com`, `mypdfsoftware.com`, `webpdfinstallerstudio.com`, `securedocinstaller.com`, `recipeappfeedback.com`, `launchwindowtech.com`.

The first ten and `securedocinstaller.com` have relevant download/preparation associations or prior research context; `recipeappfeedback.com` and `launchwindowtech.com` are separate observed references and should not automatically be treated as prep-gate hosts.

## Detection and hunting

See [`rules/cookup_cluster.yar`](rules/cookup_cluster.yar) for **experimental static YARA pivots**, [`rules/cookup_cluster_network.yml`](rules/cookup_cluster_network.yml) for **Sigma-style network-log hunting**, and [`rules/hunt_queries.md`](rules/hunt_queries.md) for practical URI/endpoint queries.

**Rule handling guidance:** use domain-specific matches and the multi-parameter URL forms for hunting; avoid blocking solely on `init=prep`, `FetchRemoteBlob`, shared runtime components, or certificate publisher name. YARA and Sigma examples require testing against a benign corpus and known cluster samples before production deployment. Network coverage depends on full HTTP URLs/SSL inspection; DNS-only telemetry cannot see query strings.

## Gaps / future lab validation

- Recover an authentic non-empty `init=fin` response or second-stage payload; capture its hash, imports, process tree, and capabilities before making claims about its purpose.
- Compare extracted proprietary installer methods for new PantryLane/RecipeRover/NomadicCookNow variants against the investigated GooPDF/CookUp logic.
- Validate individual Authenticode signatures (chain, timestamp, certificate subject, signing status) rather than relying on reported publisher metadata.
- Investigate whether the different URL templates represent one backend, multiple affiliates, or separate actors using a common kit.

**Attribution:** This repository documents **technical overlap and investigative clustering**, not conclusive shared operator attribution. Publication date: 2026-11-01. Confidence may change as new samples are exercised.

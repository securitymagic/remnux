# DuskReader: Comparison of Two Rust Viewer Builds and a Suspected CLOUDHAZE Connection

**Analysis date:** 2026-10-17  
**Status:** Research in progress; attribution and full capabilities not confirmed  
**Scope:** Two Windows PE samples examined with static analysis (Malcat, FLOSS, raw-byte review) and limited Frida dynamic tracing in FLARE-VM.

> **Assessment:** The samples share DuskReader branding and document-viewer functionality. The `1bd7…` build additionally reconstructs an obfuscated remote hostname and produces `https://updatedrun.com/updater/goal` at runtime. The `b24e…` build is a plausible earlier/prototype or differently configured build without the observed networking component. Their chronological relationship and the absence of malicious logic in `b24e…` are **not proven**. The `1bd7…` implementation is **consistent with**, but not yet definitively attributable to, the QuartzLine/CLOUDHAZE cluster.

## Samples

| Property | Sample A — candidate precursor | Sample B — network-capable build |
|---|---|---|
| SHA-256 | `b24e3c032e13af00606c9fc2047d16209caa4a14c93210bb2b3c3192421ef635` | `1bd7c3aff7742a28d3664cc7579d34f63189e04120fe9d75e26c910251456da8` |
| Product metadata | DuskReader PDF Viewer | DuskReader Docs Viewer |
| Version metadata | `1.0.0.0` | `2.1.4633.0` |
| Language / framework | Rust, Windows GUI | Rust, Windows GUI |
| Size | 4,317,184 bytes | Not independently established in this analysis |
| Build-path artifact | `D:\a\automatic-app-generation\automatic-app-generation\app13\target\release\build\duskreader-d1fc0186e415279d\out\app.rs` | `.\apps\duskreader\target\release\build\duskreader-573444d89a1639f5\out\app.rs` |
| Viewer/config code | `src\pdf_renderer.rs`; `duskreader_config.json` with `recent` processing | `struct RecentFilesConfig`, `duskreader_config.json` and updater-related artifacts |
| Obfuscated network hostname | Not identified | Confirmed `updatedrun.com` |
| Observed DNS/connect | Not observed in tests to date | `getaddrinfo("updatedrun.com")`; attempt to connect to `192.64.119.17:443` |
| Installation-state file | Not observed | `%LOCALAPPDATA%\DuskReader\config.txt`, UUID and `setup_done=false` |
| Remote tasking / command execution | Not established | Suspicious strings; **execution not demonstrated** |

Version fields and source/build paths are developer controlled. Neither proves release chronology or common source history by itself.

## Shared features and possible development lineage

Both binaries present as DuskReader document viewers and contain overlapping document/configuration concepts, including recent-file handling. Sample A's config routine (`sub_140013490`) attempts to read `duskreader_config.json`; during one trace the file was absent (`CreateFileW` failure, last error 2). Sample B also contains recent-file/configuration structures, so its viewer features do not appear to be a mere placeholder.

**Hypothesis — earlier test build:** Sample A could be a relatively clean prototype produced during application generation; Sample B could incorporate a later network module or added backdoor. Supporting observations are the smaller/earlier-looking version metadata, shared application identity, and the extra networking/updater/installation state in B. Alternative explanations include sibling builds using a common template or functionality in A not yet reached by testing. **Confidence: moderate for a shared DuskReader application concept; low-to-moderate for a direct chronological predecessor-successor relationship.** No source-code diff, compiler-level function match, or build timestamps have established lineage.

## Sample A: observations

- Product metadata: **DuskReader PDF Viewer**, v1.0.0.0; unsigned in the examined metadata.
- Document-viewer code and recent-file configuration were recovered. `sub_140035830` is involved in application startup and command-line/GUI processing; it invokes `sub_140013490` and `sub_140015010`.
- No DNS lookup, outbound connection, explicit C2 hostname, or command-execution workflow was identified in the tests performed **so far**.
- A `new_galactic_empire` heuristic YARA hit was associated with a general PDF-viewer string; that is **not** sufficient attribution evidence.

**Interpretation:** No suspicious network behavior demonstrated, **not** a declaration that the file is benign.

## Sample B: observations

### On-disk and runtime state

Frida tracing established creation of:

```ini
# %LOCALAPPDATA%\DuskReader\config.txt
uid=4e9b0482-ec44-402f-a07a-0e17c5e238e5
setup_done=false
```

The UUID above is a **single sandbox observation**, not an invariant detector. Sample B also contains updater/network implementation references (`src\updater.rs`, `reqwest`, `hyper`, Tokio), plus strings associated with `/goal`, `/check`, `/updater`, `uid`, `action`, `check`, `update`, `resolution`, `register`, `setup_done`, `CMDRES`, `stdout`, `stderr_truncated`, `exit_code`, and `duration_ms`. These are **capability leads**; strings alone do not prove that remote shell tasks were received or executed.

### Encoded hostname

The literal byte sequence `updatedrun.com` was **not** found in the sample's raw file contents. Instead, `.rdata` contains two encoded fragments used by `sub_140027C21`:

| VA | Encoded bytes | Exact decoded result | Length |
|---|---|---|---|
| `0x1402CEC87` | `82 84 7F 83 9D 95 9B B0 BA BA` | `updatedrun` | 10 |
| `0x1402CEC91` | `70 83 88` | `com` | 3 |

The decoder `sub_140022532` resets an 8-bit additive key to `0xF3` per invocation and then increments it by `0xF9` after each byte:

```python
key = 0xF3
for encoded_byte in fragment:
    decoded_byte = (encoded_byte + key) & 0xFF
    key = (key + 0xF9) & 0xFF
```

Equivalently, `P[i] = (C[i] - 13 - 7*i) mod 256`. The *reset between fragments* matters: the second three-byte segment decodes to `com` only with a fresh key. This is reversible string obfuscation, not secure encryption.

The relevant call sites are within hostname constructor `sub_140027C21` (`0x140027C40` for ten bytes; `0x140027C5A` for three bytes). Its caller `sub_140022810` formats the hostname into an application URL.

### Confirmed URL construction, not yet confirmed HTTPS request

A Frida hook on string-formatting helper `sub_1400221C6` captured its output from return RVA `0x228A1` (inside `sub_140022810`):

```text
field[0] = 0x3c
field[1] = 0x6beb10
field[2] = 0x23
Candidate string: https://updatedrun.com/updater/goal
```

For this returned structure, the observed string pointer is field 1 and string length field 2; field 0 plausibly represents capacity. This **confirms URL construction in process memory**, not the HTTP method, payload, or that this *specific* URL was successfully requested. Separately, Frida observed `getaddrinfo("updatedrun.com")` and an attempted `connect` to `192.64.119.17:443`. The trace does not independently prove DNS answer association, successful TLS completion, or receipt of tasks.

### Relevant static call chain

```text
.rdata encoded bytes
   -> sub_140022532    rolling additive decode (start F3, step F9)
   -> sub_140027C21    decode two fragments, construct hostname
   -> sub_140022810    construct URL containing hostname
   -> sub_1400016F0    downstream operation; semantics under investigation
```

There is also a second reference from `sub_140024CE7` to the hostname builder; the exact string template and usage have not been fully resolved.

## CLOUDHAZE / QuartzLine comparison and confidence

Expel's **15 October 2026** analysis describes **QuartzLine**, which it identifies as tracked by Mandiant as **CLOUDHAZE**, as a working PDF viewer hiding a backdoor. Publicly reported samples use deceptive viewer functionality and remote communications. Independent campaign reporting also describes URLs with a two-word path under an apex domain. See references below.

| Evidence dimension | DuskReader B | Assessment |
|---|---|---|
| Genuine-looking viewer lure | Viewer functionality and config structures present | **Moderate similarity**; broad enough to occur elsewhere |
| Rust implementation | Confirmed Rust executable | **Weak alone**; ecosystem choice is common |
| Concealed hostname | `updatedrun` and `com` decoded separately at runtime | **Moderate similarity** in technique |
| Decoder mechanics | Progressive addition, start `F3`, step `F9`; reset per fragment | **Potentially strong** if *implementation/structure* matches a confirmed member; same arithmetic has appeared in other analyzed viewer samples, but here we have **not** performed a function-by-function comparison against a known reference binary |
| URL structure | `https://updatedrun.com/updater/goal` | **Moderate** cluster consistency; two dictionary-like path segments are not unique |
| Local UID and setup state | Confirmed | **Suggestive**, but no matched schema confirmed |
| Server protocol, response codec, task objects | Not recovered | **Major missing evidence** |
| Codebase lineage | Similar DuskReader-specific viewer concepts between A and B; no verified cross-family source diff | **Unproven** against CLOUDHAZE |

**Attribution confidence for Sample B: low-to-moderate (plausible CLOUDHAZE/QuartzLine relationship, unconfirmed).** This is an analytical judgment, not a vendor classification or calibrated probability. Obfuscation, language, and URL layout are supportive *in combination*, but none uniquely identifies the family. Confirmation would require matching a known CLOUDHAZE implementation by distinctive code, decoded protocol, task/result schema, related infrastructure, or high-quality independent sample-level reporting. **Sample A should not automatically inherit Sample B's attribution.**

## Indicators of compromise and investigation leads

The following are from this investigation; applicability and evidentiary type are explicit.

| Type | Value | Sample | Confidence / qualification |
|---|---|---|---|
| SHA-256 | `1bd7c3aff7742a28d3664cc7579d34f63189e04120fe9d75e26c910251456da8` | B | High-confidence sample identifier; suspected network-capable build |
| SHA-256 | `b24e3c032e13af00606c9fc2047d16209caa4a14c93210bb2b3c3192421ef635` | A | High-confidence sample identifier; **not established malicious** |
| Domain | `updatedrun.com` | B | High-confidence embedded/runtime reconstructed endpoint; DNS lookup observed |
| URL | `https://updatedrun.com/updater/goal` | B | High-confidence **constructed URL**, not separately verified as sent HTTP request |
| IP:port | `192.64.119.17:443` | B | Observed outbound connection attempt; infrastructure ownership/response unverified; IP may be shared/dynamic |
| File path | `%LOCALAPPDATA%\DuskReader\config.txt` | B | Confirmed artifact; generic path alone not definitive |
| File content | `setup_done=false`; `uid=<UUID>` | B | Confirmed in one sandbox execution; UID changes by installation |
| Filename/config | `duskreader_config.json` | A and B | Application artifact; **not malicious on its own** |
| Other possible paths | `/check`; `/updater` | B | String evidence only; **not confirmed full network URLs** |

**Detection caution:** Domain and full-path indicators can be high-signal in context; hashes identify the analyzed files exactly. Do not block a generic filename or UUID independently. Do not treat all strings matching `goal`, `check`, or `update` as IOCs.

## Outstanding questions / recommended next tests

1. Capture the **HTTP method, headers, request body and decrypted response** for Sample B in a controlled sandbox. Does its UUID appear in registration or polling messages? Is `/updater/goal` actually requested?
2. Establish whether `CMDRES` and the stdout/stderr fields are reachable from server-response handling; test only with isolated/mock infrastructure.
3. Compare distinctive application functions and Rust source-path artifacts across A and B, excluding statically linked third-party crates, to test the precursor hypothesis.
4. Compare Sample B's decoder **function bytes/control-flow graph**, URL builders, and protocol codec against a confirmed CLOUDHAZE/QuartzLine reference sample; do not rely on string-level similarities.
5. Determine whether the IP was returned by the observed DNS resolution and whether TLS handshake or HTTP request completed.
6. Resolve the independently referenced `/check` flow and updater-related handlers.

## Defogger tooling note

`defogger5_1.py` extends the existing additive/XOR analyzer to identify **RDX encoded pointer + R8D length + direct CALL** patterns alongside the earlier RCX/EDX decoder call style. It also associates adjacent stem/TLD fragments when the decoded labels, data layout, decoder profile and calls agree, instead of decoding an entire packed buffer as one string. Reported domains are **static candidates**, never automatically asserted to have been contacted. Tested on a synthetic DuskReader-equivalent call/decoder fixture; the original sample binaries were not available for a full end-to-end regression run in this workspace.

## Sources

- Expel, **“QuartzLine: A working PDF viewer with a backdoor inside,”** 2026-10-15: https://expel.com/blog/quartzline-a-working-pdf-viewer-with-a-backdoor-inside/
- ThreatFox campaign-associated URL report (two-word endpoint convention; attribution is reporter-provided): https://threatfox.abuse.ch/ioc/1965051/
- Analyst's Malcat disassembly, FLOSS/strings extraction, Frida console output, and byte-level inspection for the two hashes listed above. Primary evidence for DuskReader's internal findings is the lab material, not the external campaign reports.

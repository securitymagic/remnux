# DragonsGate: A Modified 7-Zip DLL Hiding an In-Memory PE Loader

**Technical malware analysis | November 12, 2026**  
**Scope:** CoolPDF / `AppPDF_322784.exe` — Inno Setup native loader investigation

> **Update — 12 November 2026:** Later Ghidra analysis and controlled Frida runs resolved a **digit-parity response check** and identified an **environment-dependent branch**. Forcing the latter to return false allowed two additional HTTP requests and a temporary-file processing attempt. The third response had an empty body; **no second-stage payload or PE execution was observed**.

## 1. Executive summary

A signed PDF utility installer distributing **CoolPDF 2.1.1.0** contains a modified `is7z.dll` component that preserves expected 7-Zip exports while incorporating code for data transformation, command dispatch, and in-memory PE loading.

**Principal finding:** The extracted DLL matches a custom DragonsGate YARA hunt on a distinctive 32-byte constant and LFSR-seed indicator. Ghidra confirms executable code copies that exact constant, applies a bitwise LFSR-style transformation, and provides a manual mapper for 32-bit PE files. This is stronger than a static string match alone.

Static analysis also exposed XOR-obfuscated `LP|` and `RP|` command prefixes. The former invokes a file-loading routine with a custom four-byte length trailer; the latter leads to the staged processing routine containing the PE mapper. The installer was observed contacting `innodocumentsetup.com` before its welcome GUI. Later early-child instrumentation and a controlled runtime environment-check bypass reached a second and third HTTP request, followed by a failed `PG|` operation on a zero-byte temporary file. The payload-loading and manual-mapping hooks still did **not** show successful execution.

**Scope / confidence:** High confidence that this DLL contains a DragonsGate-related loader implementation; **not** a confirmed successful infection chain or recovered second-stage payload. The first response’s digit-parity check is confirmed, but the server-side decision to deliver a payload and successful next-stage execution remain unproven.

## 2. Sample details and indicators

| Artifact / property | Observed value |
| --- | --- |
| Installer filename | `AppPDF_322784.exe` |
| Installer SHA-256 | `2f4502f29a7c61ebb300849d07b182a8f07efe8f72c2b84b10c74989e851158f` |
| Installer size | 29.38 MB (VirusTotal UI) |
| Installer archive format | Inno Setup 6.1.0 (Unicode), as identified by `innounp`; HTTP User-Agent reports `Inno Setup 6.2.0` |
| Installed application / GUI | CoolPDF 2.1.1.0 |
| Code-signing subject | Serve-o-lution LLC |
| Certificate issuer | Sectigo Public Code Signing CA EV R36 |
| Certificate SHA-1 thumbprint | `913746695BF2AB84C4C648475B25655F933365BC` |
| Certificate serial | `0D AB B7 75 27 78 35 05 2B C6 E8 EB BA 83 5A B1` |
| Extracted native DLL | `{tmp}\is7z.dll`; displayed as `7z.dll` in VirusTotal |
| DLL SHA-256 | `a963c58c75a688282777a34e4b404a1dfe0fd2f07d28e5b8e3fc6574b26f49b5` |
| Contacted host | `innodocumentsetup.com` |
| Observed GET URL | `https://innodocumentsetup.com/?app=e0c8a6bb&re=43c1fe30&xn=p` |
| Original HTTP response body | `6F61B0EC861FB093FB4E1CCD5FFDE96D` (32 ASCII hex characters) |

![VirusTotal contacted URL and domain for AppPDF installer](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_01.png)

\*Figure 1. Fig. 1 — Installer's network relationship as displayed in VirusTotal.\*

![Certificate chain showing Serve-o-lution LLC](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_02.png)

\*Figure 2. Fig. 2 — Code-signing certificate details supplied with the sample.\*

Hashes, certificate fields and network indicators are from the screenshots and analysis session. Domain and URL are investigative indicators, not proof that every request to the infrastructure is malicious. No certificate-chain validation was performed independently in this report.

## 3. Installer unpacking and suspicious native DLL

`innounp` extracted the Inno Setup archive. The package contained ordinary-looking CoolPDF .NET application components such as `CoolPDF.App.exe`, `CoolPDF.App.dll`, `CoolPDF.Core.dll`, and `CoolPDF.Engine.dll`, alongside a temporary native `is7z.dll`.

![innounp archive extraction showing is7z.dll and CoolPDF components](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_03.png)

\*Figure 3. Fig. 3 — innounp extraction shows {tmp}\is7z.dll beside the application payload.\*

The DLL retains 15 conventional-looking 7-Zip archive and codec exports, including `CreateObject`, `CreateDecoder`, `CreateEncoder`, `GetHandlerProperty`, `GetNumberOfFormats` and `SetCodecs`. No suspicious `cx1`/`cx2`/`cx3` exports were present in the observed export table. The malicious-capable functionality is instead reached through internal functions.

![VirusTotal custom YARA rule detection of DLL](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_04.png)

\*Figure 4. Fig. 4 — Custom DragonsGate YARA match on the extracted DLL. The screenshot shows Google TI as undetected; this is not a claim that every antivirus engine was negative.\*

The user's `DragonsGate_SharedConstant_LFSR_Hunt_20261104` rule matched the extracted DLL. YARA disclosed the exact static locations below:

| Pattern | File offset | RVA / section |
| --- | --- | --- |
| 32-byte shared constant | `0xD9408` | `0xDA408`, `.rdata` |
| Four-byte seed pattern | `0x1A1B` | `0x261B`, `.text` |
| Four-byte seed pattern | `0xDFB9D` | `0xE0B9D`, `.rdata` |
| Four-byte seed pattern | `0xEAEFD` | `0xEBEFD`, `.rdata` |
| Four-byte seed pattern | `0xF0261` | `0xF1261`, `.rdata` |

```text
0F E7 E7 1C A4 52 75 33 49 8D A9 D3 D9 9D 0E 43
7C 7D 25 79 74 20 E0 7D FB F5 06 AA 53 CF C3 6D
```

The short `00 00 00 95` seed pattern is weak in isolation. Its combination with the unusual 32-byte constant, and the later code references, is the substantive detection signal.

## 4. Reverse engineering: transformation and PE mapping

### 4.1 Shared constant used by executable code

Ghidra image base was `0x10000000`, placing the 32-byte constant at `0x100DA408`. A cross-reference at `0x1000293C` points to it. The surrounding decompiled function, `FUN_10002893`, copies 32 bytes from a global buffer, transforms that data, copies the shared constant immediately after it, then transforms the resulting 64-byte region.

```text
memcpy(work, global_buffer, 0x20);
FUN_10002606(work, 0x20);
memcpy(work + 0x20, &DAT_100da408, 0x20);
FUN_10002606(work, 0x40);
```

The code above is condensed pseudocode; it retains the observed operation order. The transformation routine initializes its internal state for each invocation, so the second call restarts the sequence across the full 64-byte buffer.

![Ghidra cross reference showing PUSH DAT_100da408 at 1000293C](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_05.png)

\*Figure 5. Fig. 5 — Direct code reference to the distinctive constant from the loader routine.\*

### 4.2 LFSR-style bitwise transformation

The implementation in `FUN_10002606` iterates over `length × 8` bits, initializes a 32-bit state to `0x95000000`, shifts that state right, conditionally inserts a high bit, and mutates buffer bits in place. This is consistent with an LFSR-style stream transformation; the full tap/feedback behavior was not independently reimplemented or test-vector verified here.

```text
state = 0x95000000;
for each input bit:
    feedback = compute_from_state(state);  // Ghidra loop
    state = (state >> 1) | (feedback ? 0x80000000 : 0);
    update_one_bit_of_buffer();
```

### 4.3 Custom trailer and file-to-buffer initialization

`FUN_10002e1a` checks that the last four bytes of an input buffer, interpreted as a little-endian integer, equal `buffer_length - 4`. This is a length-consistency marker, *not* cryptographic authentication. `FUN_10002cfb` reads a supplied path through `CreateFileW` / `ReadFile` and applies this check. On success, `FUN_10002751` copies the bytes to heap storage and updates global pointer `DAT_10118C5C` and size `DAT_10118C60`.

```text
// FUN_10002e1a — simplified
if (buffer != NULL && size > 4 &&
    read_le32(buffer + size - 4) + 4 == size)
    return true;
```

### 4.4 Manual in-memory PE loader

`FUN_100023ba`, reached via wrapper `FUN_1000238e`, checks DOS and NT headers (`MZ`/`PE`), restricts machine type to `0x14C` (x86), computes an image allocation, copies PE headers and sections, calls helper routines consistent with relocation/import processing, and transfers control to a mapped DLL entry point. It also retains the calculated entry-point pointer when not invoking a DLL entry point.

```text
// High-level actions in FUN_100023ba
validate_MZ_PE_and_x86_headers();
allocate_image_memory();
copy_headers_and_sections();
apply_relocations_if_needed();
process_imports_and_protections();
if (mapped_image_is_dll)
    DllMain(image_base, DLL_PROCESS_ATTACH, NULL);
```

This supports **manual PE mapping capability**. Helper labels for relocations, import handling, and protection are inferred from call order and PE-header access; those helpers were not all independently audited. `FUN_10002893` contains repeated mapping, export-resolution and indirect-call patterns consistent with staged processing.

Input file / bufferSource provided by caller

→

Trailer validationFUN\_10002e1a

→

Buffer initializationFUN\_10002751

→

LFSR + shared constantFUN\_10002606 / 10002893

→

PE mappingFUN\_100023ba

This diagram illustrates the identified code path, not a fully observed execution trace.

## 5. Hidden command interface

The internal dispatcher `FUN_100049EE` calls decoding helpers to recover command prefixes. `FUN_10004DCE` uses a per-character UTF-16 XOR transformation: `decoded[i] = encoded[i] XOR (0xA7 + i)`, for three characters.

| Encoded UTF-16 bytes | Decoded prefix | Observed code path |
| --- | --- | --- |
| `EB 00 F8 00 D5 00` | `LP|` | Passes trailing string to `FUN_10002CFB` for file read and validation |
| `F5 00 F8 00 D5 00` | `RP|` | Calls `FUN_10002893` with trailing string and another derived argument |

The dispatcher is called by both `FUN_10004968` and `FUN_10004F6F`, and another handler, `FUN_100030AA`, can process inputs not recognized by the first. Its small wrapper `FUN_10003066` uses the same string-XOR method; later instrumentation recovered the `PG|` prefix in this secondary branch.

A worker-thread helper, `FUN_1000163B`, executes callbacks while pumping GUI messages and updating an `msctls_progress32` control. This is a normal UI pattern by itself and does not establish an IPC-based activation route.

**Command-interface limitation:** `LP|` and `RP|` are internal UTF-16 input prefixes. They are *not* established installer command-line arguments, HTTP response strings or network commands.

## 6. Pre-GUI dynamic analysis and network tests

### 6.1 Network request and response

Fiddler captured an HTTPS GET to `innodocumentsetup.com`, with query parameters `app=e0c8a6bb`, `re=43c1fe30` and `xn=p`, and a User-Agent of `Inno Setup 6.2.0`. The original HTTP 200 response body was 32 printable hex characters. Subsequent Ghidra and Frida analysis established its use as input to a local `VER|` digit-parity check (section 6.4).

![Fiddler request to innodocumentsetup.com and 32-character response](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_06.png)

\*Figure 6. Fig. 6 — Captured installer request and original hexadecimal response body.\*

### Protocol differences from previously analyzed DragonsGate variants

The observed request structure in this Inno Setup / 7-Zip implementation (`?app=e0c8a6bb&re=43c1fe30&xn=p`) differs from the earlier `init=prep` and randomized-parameter requests investigated in other DragonsGate builds. **Subsequent analysis confirmed that this variant does implement a digit-sum parity check** for the `VER|` response (section 6.4), although that does not establish identical protocols across variants. The `LP|` and `RP|` prefixes are *internal DLL commands*, not observed HTTP response instructions.

### 6.2 Controlled response comparison

| Test | Returned response | Observed GUI result |
| --- | --- | --- |
| Baseline | `200 OK`, original 32-character hex string | CoolPDF setup GUI opened |
| Modified body | `200 OK`, 32 zero characters | No visible difference |
| Denied | `403 Access Denied` (Fiddler AutoResponder template) | Setup GUI still opened |

![Fiddler all zeros response during test](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_07.png)

\*Figure 7. Fig. 7 — AutoResponder with all-zero token body.\*

![Fiddler HTTP 403 response during test](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_08.png)

\*Figure 8. Fig. 8 — AutoResponder HTTP 403 Access Denied test.\*

The experiments establish that successful receipt of this specific body is **not required to display the visible setup GUI**. They do not demonstrate whether a valid response is required for hidden payload activation. No new Fiddler traffic was observed while finishing the installation in the reported instrumented run.

### 6.3 Early-child Frida instrumentation

Attaching Frida to the initial executable did not work because Inno Setup transfers execution to a child `AppPDF_322784.tmp` in an `is-*.tmp` directory. Late attachment to the child located and hooked `is7z.dll`, but missed earlier execution. A Windows process-creation interception approach subsequently suspended the child before execution, installed Frida hooks and resumed its primary thread.

```text
[09:55:06.207] Parent intercepted AppPDF_322784.tmp creation
[09:55:06.223] Attaching to suspended child PID=3460
[09:55:06.257] Child hooks installed; resuming thread
[DG] Loaded is7z.dll base=0x729a0000
[DG] Hooked dispatcher RVA=0x49ee
[DG] Hooked load_file RVA=0x2cfb
[DG] Hooked save_buffer RVA=0x2751
[DG] Hooked process_payload RVA=0x2893
[DG] Hooked manual_map RVA=0x23ba
```

The console showed the following dispatcher inputs, including one additional occurrence during continuation through the installation:

```text
[DG] dispatcher #1 input="CK|2.1.1.0|0"  → returned 0
[DG] dispatcher #2 input="CoolPDF.App.exe" → returned 0
[DG] dispatcher #3 input="CoolPDF.App.exe" → returned 0
[DG] dispatcher #4 input="CoolPDF.App.exe" → returned 0
```

`CK|2.1.1.0|0` is an **observed input**; its exact downstream handler and purpose were not conclusively established. Returning zero from `FUN_100049EE` indicates that particular handler did not report handling the input, not necessarily that the installer discarded it.

| Hooked routine | Observed hits | Interpretation |
| --- | --- | --- |
| Dispatcher, `0x49EE` | 4 | Command-processing function executed |
| File load, `0x2CFB` | 0 | File-based payload-loading path not observed |
| Buffer store, `0x2751` | 0 | Input-buffer initialization path not observed |
| Stage processing, `0x2893` | 0 | LFSR/manual-mapping caller not observed |
| Manual PE mapper, `0x23BA` | 0 | Manual mapping not observed |

![CoolPDF setup welcome screen](DragonsGate_Modified_7Zip_Loader_Analysis_images/figure_09.png)

\*Figure 9. Fig. 9 — CoolPDF 2.1.1.0 GUI, displayed despite the controlled HTTP response changes.\*

The saved Python launcher log contains process-interception events, but not the `[DG]` JavaScript trace lines. The function-hit observations above are transcribed from the session's console output supplied during analysis. Counts apply to the instrumented session, not every possible execution path.


### 6.4 Gate 1 — server response digit-parity check (confirmed in Ghidra and Frida)

The installer passes the 32-character HTTP response to the DLL as `VER|<response>`. `FUN_10004968` recognizes the four-character `VER|` prefix and calls `FUN_1000465D` on the suffix. The latter trims the suffix at a space, tab or line break, adds **only ASCII decimal digits** (`0`–`9`) and chooses one of two output strings. The normal passing condition is **nonzero, even digit sum**, subject to its separate `FUN_1000383E()` preliminary check. The special suffix `.` bypasses the ordinary zero/odd rejection condition.

Simplified logic from the decompiled function (not a full reimplementation):

```c
sum = 0;
for (each UTF16 character c before whitespace)
    if (c >= '0' && c <= '9') sum += c - '0';
if (suffix != "." && (sum == 0 || (sum & 1) != 0))
    result = failure_string;  // observed "A"
else
    result = success_string;  // observed "OK"
```

| Response source | 32-character body | Digit sum | Observed DLL output |
| --- | --- | ---: | --- |
| Unmodified live response, later run | `F357AF7B013FB557063C3765641C4C27` | 97 (odd) | `A` |
| Fiddler AutoResponder replay | `DD8CCF3E63FD7D2B8CD9986124FF7D81` | 92 (even) | `OK` |

The output is pushed into an internal 32-slot, 4 KiB-per-slot string stack using `FUN_10001E9B` (push); `FUN_10001E33` pops a value. `FUN_10001D67` provides a structured request/result interface, although this particular routine was **not shown executing** in the captured console trace; the passive interface-hook initialization requires separate JSONL confirmation. Importantly, `OK` is a **local DLL parity result**, not proof of server authorization or stage-two execution.

### 6.5 Gate 2 — environment checks, forced-false dynamic bypass

When `CoolPDF.App.exe` reaches the fallback branch of `FUN_10004968`, the DLL calls `FUN_1000411C`. Its decompiled implementation inspects the module filename (`GetModuleFileNameW`), enumerates files (`FindFirstFileW` / `FindNextFileW`), loaded modules (`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`), and processes (`TH32CS_SNAPPROCESS`), plus additional opaque checks. Matching target values have not all been decoded. It returns a Boolean; `true` drives the observed `invalid_name` path, whereas `false` calls `FUN_1000448B` and then `FUN_10004D1A`.

`FUN_1000448B` profiles two `HKEY_LOCAL_MACHINE` registry paths through wrappers consistent with `RegOpenKeyExW`, `RegEnumKeyExW`, `RegQueryValueExW` and `RegCloseKey`. It updates the environment flag word at `DAT_10118C64`. `FUN_10004D1A` takes the low 16 bits of `FUN_100043A9()` and pushes the resulting **decimal string** into the output stack. The flag meanings and other checks remain partially unresolved.

Using Frida 17.7.3 in the already suspended Inno child, the analysis **overrode only the function return** at `is7z.dll + 0x411C` (original code still executed). Representative patch:

```javascript
Interceptor.attach(module.base.add(0x411c), {
  onLeave(retval) {
    const original = retval.toInt32();
    send({ event: 'env_gate_forced_false', originalReturn: original, forcedReturn: 0 });
    retval.replace(0);
  }
});
```

This was combined with a previously captured positive-even-sum response through Fiddler AutoResponder, in an isolated FLARE-VM; it is **not the behavior of the unmodified installer on the tested host**.

The runtime trace directly confirms the branch override and subsequent result:

```text
is7z.dll+0x411C: originalReturn=1, forcedReturn=0
message sink from is7z.dll+0x4D5A: "4224"
"VER|." -> "OK"
"P|1|2.1.1.0|4224"
"UPD|1|2.1.1.0|4224"
```

**Causality in this controlled run:** with the same earlier response replayed as `OK`, changing the environment-check result from `1` to `0` exposed the registry-profiling/decimal-output path and allowed the installer to continue into additional network operations. The `4224` value was *observed*, not decoded into individual environmental flags.

### 6.6 Newly reached C2 sequence and empty-file stopping point

Fiddler observed the following consecutive HTTPS requests after the patched branch. URL values are **specific to this run**; do not assume these `app`, `re` and `uu` tokens are stable IOCs.

| Order | Request to `innodocumentsetup.com` | Observed response |
| --- | --- | --- |
| 1 | `/?app=e0c8a6bb&re=43c1fe30&xn=p` | Replayed `DD8CCF3E63FD7D2B8CD9986124FF7D81` (32 ASCII chars) |
| 2 | `/?app=4624ea57&re=d6f942aa&xn=p` | `FBC8761484A07C102D95094AF21F1AEE` (32 ASCII chars) |
| 3 | `/?app=98e71c7b&re=0e5c0bf5&uu=e083c989&xn=f` | HTTP 200; **`Content-Length: 0`** |

The second response is present in the WinHTTP plaintext read trace. The third response is documented in Fiddler as 200 with no entity body. The meaning of `uu` and `xn=f` is **unknown**; the changing parameters mark a distinct request, not proof that the server intentionally rejected the host.

![Fiddler request sequence with second response](DragonsGate_Modified_7Zip_Loader_Analysis_images/gated_fiddler_second_response.png)

*Figure 10. Additional request after bypass and its 32-character response.*

![Fiddler third request with zero-length response](DragonsGate_Modified_7Zip_Loader_Analysis_images/gated_fiddler_empty_third.png)

*Figure 11. The third request returned HTTP 200 and `Content-Length: 0`.*

After the third request the DLL was asked to process a temporary file via the **separate** `PG|` path:

```text
PG|C:\Users\drago\AppData\Local\Temp\is-1BGS7.tmp\4F5C.tmp
    -> BAD|0
```

The trace places `BAD|0` at `FUN_10002E47` → `FUN_10001E9B` (string push from call site `is7z.dll+0x2F14`). This **does not establish** a call to the different `LP|` file reader at `FUN_10002CFB`. In the observed run, neither the dedicated file-load, buffer-store, stage-processing nor manual mapper hooks reported invocation.

In a subsequent visual observation during the setup's `Starting CoolPDF... Please wait.` window, a similarly named `.tmp` file appeared **alongside `is7z.dll`**, remained **0 bytes** across refreshes, and was deleted once the ordinary setup GUI appeared. The screenshot shows a later run, so its random temp filename differs from `4F5C.tmp` in the logged run. This is strong evidence of an empty download/output artifact and cleanup, **not** proof of how the `PG|` routine would react to a valid payload.

![Zero-byte staging file alongside is7z.dll](DragonsGate_Modified_7Zip_Loader_Analysis_images/gated_zero_byte_temp.png)

*Figure 12. Later run: a zero-byte staging file, the modified DLL, and two 32-byte temporary files in the Inno temp directory.*

![CoolPDF updating window](DragonsGate_Modified_7Zip_Loader_Analysis_images/gated_coolpdf_wait.png)

*Figure 13. Temporary setup progress window, before the staging file is removed and the standard GUI appears.*

### 6.7 Resulting execution chain (confirmed vs. inferred)

```text
Inno parent -> pre-GUI AppPDF_322784.tmp child
  -> load modified is7z.dll
  -> GET #1 / VER|<32 ASCII chars>
  -> digit-parity result: A (odd) or OK (positive-even)
  -> CoolPDF.App.exe fallback command
  -> FUN_1000411C environment check [normally true on analysis VM]
       true  -> invalid_name / no further observed stages
       false -> registry profiling + 16-bit decimal output [forced by Frida]
  -> VER|. -> OK; P|1|... and UPD|1|... observed
  -> GET #2 (32 ASCII chars) -> GET #3 (empty HTTP 200)
  -> zero-byte .tmp -> PG|<path> -> BAD|0
  -> temporary file cleanup -> normal installer GUI
  -> no second-stage PE recovered or observed executing
```

This identifies **two distinct locally implemented conditions**, one response-content check and one environmental gate. Only the environmental check was altered in the documented Frida bypass; the first response was controlled using Fiddler AutoResponder. Server-side payload selection remains unproven, and there is no claim that `BAD|0` was bypassed or that execution progressed into the in-memory PE mapper.

## 7. Detection and hunting opportunities

Defenders can hunt this implementation using a layered approach, prioritizing the precise static constant and supporting code or behavioral context over broad PDF-software indicators.

| Signal | Practical use / caveat |
| --- | --- |
| Exact 32-byte constant | High-value static family pivot, especially if combined with decoder seed or PE-mapping code |
| `0x95000000` / seed bytes | Supporting indicator only; four-byte matches are not specific enough alone |
| Unusual `is7z.dll` | Compare DLL hashes and code sections to trusted 7-Zip/Inno components, not filename alone |
| Hidden `LP|`, `RP|` prefixes | Potential decoded-string or memory-hunt pivots; not established network IOCs |
| Manual PE mapping operations | Correlate PE-header validation, memory allocation, relocation/import processing and indirect execution |
| Inno temporary child | Observe `AppPDF_322784.tmp` loading a modified DLL early in process life; generic temp Inno processes are normal |
| Domain, installer and DLL hashes | Exact-match IOCs for retrospective hunting; use domain context and timestamps |

#### Illustrative YARA hunting snippet (not a replacement for validated rule)

```text
rule DragonsGate_7z_SharedConstant_Research {
    meta:
        description = "Research pivot: shared DragonsGate 32-byte constant"
        confidence = "Requires corroboration"
    strings:
        $constant = { 0F E7 E7 1C A4 52 75 33 49 8D A9 D3 D9 9D 0E 43
                      7C 7D 25 79 74 20 E0 7D FB F5 06 AA 53 CF C3 6D }
    condition:
        uint16(0) == 0x5A4D and $constant
}
```

This is a simple IOC-oriented example, not the user's tested `DragonsGate_SharedConstant_LFSR_Hunt_20261104` rule. It has not been false-positive tested.

### Function / address reference

| Ghidra VA (base 0x10000000) | Role |
| --- | --- |
| `0x100049EE` | Hidden command dispatcher |
| `0x10002CFB` | Read and validate supplied file |
| `0x10002751` | Copy validated buffer to globals |
| `0x10002893` | Transformed buffer and staged processing |
| `0x10002606` | LFSR-style transformation |
| `0x1000238E` | Wrapper around manual mapper |
| `0x100023BA` | Manual x86 PE mapping |
| `0x100030AA` | Secondary string handler (`PG|` and other commands) |
| `0x10004968` | General handler: `VER|` recognition and environment-dependent fallback |
| `0x1000465D` | Digit-parity response check |
| `0x1000411C` | Environment check, forced to return false during controlled test |
| `0x1000448B` | Registry/environment profiling |
| `0x10004D1A` | Low-16-bit decimal result formatting |
| `0x10001E9B` / `0x10001E33` | String stack push / pop |
| `0x100DA408` | Shared constant data, not executable function |

## 8. Conclusions and unresolved questions

The CoolPDF installer includes a modified 7-Zip-compatible DLL that contains DragonsGate-related transformation and manual PE-mapping code. Its pre-GUI HTTP response is passed into the DLL as `VER|<token>` and handled by a **confirmed decimal-digit parity gate**. A separate environment-checking function normally returned `true` on the FLARE-VM and led to `invalid_name`; forcing that return to `false` **at runtime** exposed registry profiling, decimal output (`4224`), two additional C2 requests, and a `PG|` attempt to process a zero-byte temporary file.

The third HTTPS request returned HTTP 200 with `Content-Length: 0`. The DLL emitted `BAD|0`; the installer removed its temporary staging file and continued into the ordinary CoolPDF GUI. **No next-stage binary was downloaded or recovered, and no manual PE mapping was observed.** The evidence does not distinguish deliberate server gating from inactive delivery or other conditions, and `PG|` has not been proven to directly invoke the `LP|` / `RP|` loader path.

**Final assessment:** Confirmed DragonsGate-related native PE-loader code, local response-parity gate, environment-dependent path and controlled bypass of that path; demonstrated progression into additional network activity and a failed zero-byte file-processing operation. Stage-two delivery and successful execution remain **unconfirmed**.

Possible follow-up: trace `PG|` file handling to identify exactly why it returns `BAD|0`, or compare behavior against a known valid payload file if one becomes available. Preserve the unmodified run and the patched run separately for reproducibility.

Prepared from Ghidra decompilation, Frida 17.7.3 logs, Fiddler sessions and FLARE-VM screenshots, 12 November 2026. The testing described here was performed against an isolated research VM with a targeted Frida return-value override; the report does not distribute malware binaries.

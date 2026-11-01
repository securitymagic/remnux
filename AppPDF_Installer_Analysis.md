# AppPDF Installer Analysis — Inno Setup, Remote Check, and 7-Zip Integration

**Analysis date:** 2026-10-31  
**Status:** Preliminary / investigation ongoing  
**Environment:** Windows FLARE-VM, Fiddler, Frida 17, Process Hacker, innoextract/innounp  
**Attribution:** Possible YAPA-related distribution activity; **not confirmed**

## Executive summary

`AppPDF_479810.exe` is a PDF-themed installer discovered through a broader Google Threat Intelligence hunt. Static extraction and dynamic tracing identified a custom Inno Setup installation workflow, a remote HTTP check to `installerpdf.com`, a 32-byte server response stored as `is7zv.tmp`, and use of a bundled 7-Zip engine (`is7z.dll`). Compiled Inno Setup script strings reference `DoGuidCheck`, `DownloadPayload`, package validation/execution, and an explicit `invalid_name (scan evasion)` diagnostic.

**Important limitation:** A malicious second-stage download, the meaning of the 32-byte response, and any YAPA family relationship have **not** been confirmed. The recovered installed application files appear to provide PDF/document functionality.

## Artifacts

| Artifact | SHA-256 | Notes |
|---|---|---|
| `AppPDF_479810.exe` / `apppdf.exe` | `e71f26175f0bd7e3ad4b655ad84195fbb50c283a3570486801e2971a721f05a7` | Original installer; 30,742,064 bytes locally; GTI showed 1/72 detection |
| Extracted Inno Setup child (`apppdf.tmp`, preserved as `apppdf2.exe`) | `c5fe0fb3abf00775a0c1139d3cc15d140f8b4f9558a5b0d84eeec59a561b29a1` | 3,165,184 bytes; identical child hash listed in GTI relations for three parent installers |
| `is7z.dll` | `8fe2217b4913c93d7ba637a8956aa5374fd611b8ab99e992b67004da8ac53de9` | 32-bit 7-Zip archive component; GTI showed AppPDF as its sole listed execution parent at time of analysis |
| `embedded/CompiledCode.bin` | Not recorded | 18,947-byte compiled Inno Setup Pascal Script extracted locally |

GTI showed the same temporary installer hash as a child of `PDFConvertSetup_5639.exe` (2026-09-25), `FileReady_773581.exe` (2026-10-31), and `AppPDF_479810.exe` (2026-10-31). This suggests shared packaging or distribution infrastructure, **not** proof that all parents belong to one malware family.

## Execution flow observed

```text
AppPDF_479810.exe (original Inno Setup package)
  └─ %LOCALAPPDATA%\Temp\is-<random>.tmp\apppdf.tmp
       ├─ WinHTTP request to installerpdf.com
       ├─ %TEMP%\is-<random>.tmp\is7z.dll (loaded)
       ├─ %TEMP%\is-<random>.tmp\is7zv.tmp (32-byte data file)
       └─ Package/archive handling via is7z.dll
```

The temporary executable was copied and renamed for standalone inspection; executing that copy resulted in an Inno Setup error about a missing `apppdf2-0.bin`. This is a packaging/runtime dependency issue and **does not establish server rejection**.

## Network observations

Observed request in Fiddler:

```http
GET /?prod=f4a4a11bad9bbbb7&t=u HTTP/1.1
Host: installerpdf.com
User-Agent: Inno Setup 6.2.0
```

Two captured 32-character responses from earlier runs:

```text
B5D21287F98D90327EC441F3A24E905A
DD8CCF3E63FD7D2B8CD9986124FF7D81
```

A later run left a 32-byte file at `%TEMP%\is-VJ10F.tmp\is7zv.tmp` with these exact contents:

```text
AB1FAF9FA8BBA34258F61A1103A4B7FA
```

The MD5 hash **of the file's contents** was `1A3B1C26C833079CE55474E9B8703356`; this is distinct from the hex string stored inside it. None of these strings has yet been identified as a command, digest, or authorization token. Fiddler showed an HTTP 200 response with a 32-byte body; whether the installer accepted the value is unknown.

## Compiled installer-script clues

Strings recovered from `CompiledCode.bin` include:

```text
DoGuidCheck URL=
DoGuidCheck verify=
DoGuidCheck download=OK
DoGuidCheck download=FAIL
DownloadPayload download=OK url=
DownloadPayload download=FAIL url=
DownloadPayload validate=
DownloadPayload loadpkg=
DownloadPayload run=
CheckFilenameBanned
InitializeSetup QUIT invalid_name (scan evasion)
IS7Z_DoCommand
DONE|wrapper_launched|mode=
```

These names are consistent with remote validation and conditional package download/execution. They establish **code references**, not proof that every branch ran. The phrase `scan evasion` is an internal diagnostic string, not an independently observed evasion outcome.

## Frida evidence

A Frida 17 child-gating tracer successfully attached to both the original installer and its child:

| Event | Observation |
|---|---|
| Original PID | 10572 |
| Child PID | 7600 |
| Child attachment | Successful before resume |
| DLL loading | `is7z.dll` loaded at `0x720b0000` |
| Archive API | Three calls to `is7z.dll!CreateObject`, each returning `0x0` |
| Network API | `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReadData` |
| Read request | `WinHttpReadData(..., 0x20)` requested 32 bytes |
| Temporary artifact | `is7zv.tmp` created during the network/installation workflow |

The read size matches the observed response length. The current trace does **not** record the returned buffer contents, the number of bytes actually read, or a validation outcome.

The `is7z.dll` exports, including `CreateObject`, `CreateDecoder`, and `GetNumberOfFormats`, are consistent with an ordinary 7-Zip archive engine. There is no confirmed malicious code inside this DLL based on the evidence collected so far.

## Extracted application

`innounp` extracted a substantial .NET/WinUI document application including:

- `SolidDocuments.App.exe`, `SolidDocuments.App.dll`, `SolidDocuments.Core.dll`, `SolidDocuments.Engine.dll`
- `pdfium.dll`, `PdfSharp.dll`, `UglyToad.PdfPig.dll`, and `ClosedXML.dll`
- Windows App SDK / WebView2 dependencies

This supports the presence of a functioning document application, but does not resolve the installer wrapper's trustworthiness.

## Hunt context

The original sample was returned by an existing GTI search:

```text
name:Document_name:.exe type:peexe fs:30d+ not tag:64bits
```

The displayed search showed approximately 163 matching file indicators. This is a **discovery query, not a malware signature**.

## Outstanding questions

1. How does `DoGuidCheck` interpret the 32-byte response, and what result allows `DownloadPayload` to proceed?
2. Does the installer actually fetch a distinct additional package when validation succeeds? If so, what is its URL, hash, and behavior?
3. Are the AppPDF, FileReady, and PDFConvertSetup wrappers functionally related beyond sharing an identical temporary Inno executable?
4. Is the `is7z.dll` build a standard recompilation of 7-Zip or materially modified?
5. Which server behavior or installer logic explains the different 32-byte responses observed across executions?

## Provisional assessment

**Observed:** A low-detection PDF installer uses a custom Inno Setup script, contacts `installerpdf.com`, stores a 32-byte response in a temporary file, and initializes a bundled archive engine. The script contains download/validation/execution functions and a scanner-evasion diagnostic string.

**Not established:** A malicious second-stage payload, a successful bypass of server-side validation, or confirmed YAPA attribution. Any stronger characterization requires recovered payload behavior or control-flow evidence.

> **Operational security note:** A separate Process Hacker memory-strings export contained inherited credential-like environment variables. Those values are deliberately omitted from this report and should be rotated if valid.

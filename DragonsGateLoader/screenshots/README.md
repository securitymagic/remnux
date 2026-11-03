# Screenshot inventory

These six images are original screenshots shared during Catchlight analysis and are referenced from `../README.md`.

1. `01-malcat-buildlaunch-dispatch.png` — Malcat showing `sub_10047BCB` / custom command dispatch. **Does NOT show `invalid_name`.**
2. `02-x32dbg-environment-check-entry.png` — x32dbg stopped at `nsis7z.dll+0x44D59`; EAX at entry is not the return value.
3. `03-x32dbg-post-bypass-enumeration.png` — execution after bypass.
4. `04-x32dbg-gate-patch.png` — original x32dbg patch list confirming `74 -> 75`.
5. `05-catchlight-installer-gui.png` — GUI shown after the bypass.
6. `06-fiddler-decrypted-prep.png` — Fiddler request/response.

## Still needed for a fully illustrated public report

**Malcat invalid_name branch**: screenshot `sub_1004352A` near `0x1004358E–0x100435A0`, with `call sub_10044D59`, `test eax,eax`, branch and `call sub_10043C10` visible. A second view of `sub_10043C10` / decoded `invalid_name` bytes would reinforce the finding. Add real screenshots rather than a constructed recreation. Optionally add an x32dbg return-site screenshot with `EAX=1` and `EIP=0x742E3593`.

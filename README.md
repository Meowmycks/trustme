# trustme

BOF to impersonate TrustedInstaller via DISM API trigger and thread impersonation.

<img width="2010" height="685" alt="trustedinstaller" src="https://github.com/user-attachments/assets/3c308fd2-9026-4ef5-b112-da66b7f73ef8" />

## What this does

Elevates a Cobalt Strike Beacon from an admin context to `NT AUTHORITY\SYSTEM` with the `NT SERVICE\TrustedInstaller` SID in the token groups. This gives you the ability to modify files, registry keys, and other objects that are owned by TrustedInstaller (i.e. things that just having SYSTEM may not be enough for).

## How it works

Most public approaches to becoming TrustedInstaller start the TrustedInstaller service directly via the Service Control Manager (e.g. `sc start TrustedInstaller` or `StartServiceW`). This works, but interacting with SCM is well-understood by defenders and commonly logged.

`trustme` takes a different approach:

1. **Loads `dismapi.dll` and runs a DISM health check.** The DISM API (`DismCheckImageHealth`) internally causes `TrustedInstaller.exe` to start as a side effect of servicing stack operations. The DISM session is held open so TrustedInstaller doesn't exit before we can use it.

2. **Walks the process list using `NtGetNextProcess`.** Instead of `OpenProcess` or `CreateToolhelp32Snapshot`, we enumerate process handles indirectly through `NtGetNextProcess` and match by image name via `NtQueryInformationProcess(ProcessImageFileName)`.

3. **Impersonates a TrustedInstaller thread via `NtImpersonateThread`.** Similarly, we walk threads with `NtGetNextThread` rather than opening them by TID. Once we find a usable thread, we impersonate it and register the resulting token with Beacon via `BeaconUseToken`.

4. **Cleans up.** The DISM session is closed, `dismapi.dll` is freed from the beacon process, and handles are released. The impersonation token persists in the Beacon session until you run `rev2self`.

## Requirements

- Elevated (admin) Beacon
- `SeDebugPrivilege` must be available in the token (it is by default for admin accounts, the BOF enables it automatically)
- x64 Beacon (x86 should work but is untested)

## Building

You need `beacon.h` from the [Cobalt Strike bof_template repo](https://github.com/Cobalt-Strike/bof_template) in the same directory as `trustme.c`.

**MinGW (Linux/macOS):**

```bash
x86_64-w64-mingw32-gcc -c trustme.c -o trustme.x64.o -masm=intel -Wall
```

**MSVC (Windows, from x64 Native Tools prompt):**

```bat
cl.exe /c /GS- /Fo"trustme.x64.o" trustme.c
```

## Usage

1. Place `trustme.x64.o` (and/or `trustme.x86.o`) in the same directory as `trustme.cna`
2. Load `trustme.cna` in Cobalt Strike via Script Manager
3. From an elevated Beacon:

```
beacon> trustme
[+] SeDebugPrivilege enabled
[*] DISM health check complete, TrustedInstaller should be running
[*] Found TrustedInstaller.exe (PID: 31337)
[+] Thread impersonation successful (identity: SYSTEM)
[+] Token applied to Beacon session
[+] Now running as TrustedInstaller. Use 'rev2self' to revert.
```

4. Verify:

```
beacon> shell whoami /groups | findstr TrustedInstaller
NT SERVICE\TrustedInstaller  Well-known group  S-1-5-80-956008885-...  Enabled by default, Enabled group, Group owner
```

5. Revert when done:

```
beacon> rev2self
```

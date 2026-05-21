# SharpHoundRPC

SharpHoundRPC exposes low-level Windows RPC, Win32, and remote collection helpers used by SharpHoundCommon and SharpHound collectors. It wraps SAM, LSA, NetAPI, and remote registry operations behind C# interfaces and result types.

## When to use this package

Use `SharpHoundRPC` directly only if you need low-level RPC or interop access. If you want higher-level enumeration workflows, install `SharpHoundCommon` instead.

## Requirements

- .NET Framework 4.7.2
- Windows-focused functionality
- Appropriate privileges, network reachability, and RPC availability on target systems

## Install

```powershell
dotnet add package SharpHoundRPC
```

## Included capabilities

- SAM access through `ISAMServer`, `ISAMDomain`, `SAMServerAccessor`, and related wrappers
- LSA policy access via `LSAPolicy` for SID lookup and privilege enumeration
- NetAPI helpers for sessions, workstation information, and domain controller discovery
- Remote registry strategies using WMI or Remote Registry
- Shared `Result<T>` and related helper types for error handling

## Source and support

- Source: https://github.com/SpecterOps/SharpHoundCommon
- Issues: https://github.com/SpecterOps/SharpHoundCommon/issues
- License: GPL-3.0-only
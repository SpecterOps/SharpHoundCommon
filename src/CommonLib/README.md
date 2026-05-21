# SharpHoundCommon

SharpHoundCommon provides the high-level shared components used to build AD enumeration workflows. It includes initialization, caching, LDAP helpers, host and service processors, and registry and user-rights collection logic used by SharpHound collectors.

## When to use this package

Use `SharpHoundCommon` if you are building a collector or integration that needs higher-level enumeration behavior. This is the package most consumers should start with.

## Requirements

- .NET Framework 4.7.2
- Windows and Active Directory oriented workloads

## Install

```powershell
dotnet add package SharpHoundCommon
```

## Getting started

```csharp
using SharpHoundCommonLib;

CommonLib.InitializeCommonLib();
```

You may optionally provide an `ILogger` and a pre-created `Cache` instance to `CommonLib.InitializeCommonLib(...)`.

## Included capabilities

- Shared initialization and cache management via `CommonLib` and `Cache`
- LDAP querying and identity resolution via `LdapUtils`
- Host availability, SMB, and LDAP service checks via `ComputerAvailability`, `SmbProcessor`, and `DCLdapProcessor`
- Registry collection orchestration via `RegistryProcessor`
- User rights, SPN, and certificate-related processing helpers

## Relationship to SharpHoundRPC

`SharpHoundCommon` depends on `SharpHoundRPC` and is intended to be the higher-level entry point. Most consumers should not reference `SharpHoundRPC` directly unless they need its lower-level SAM, LSA, NetAPI, or registry APIs.

## Source and support

- Source: https://github.com/SpecterOps/SharpHoundCommon
- Issues: https://github.com/SpecterOps/SharpHoundCommon/issues
- License: GPL-3.0-only
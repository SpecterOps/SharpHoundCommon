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

## Domain resolution metadata

`SharpHoundCommonLib.Models.LdapDomainInfo` holds plain domain metadata: domain and forest names, the domain SID, naming contexts, the PDC hostname, `DomainControllerNames`, and `TrustTypes`. Additional strings may be null; collections start empty. `TrustTypes` compares target domain names case-insensitively.

`LdapConfig.AllowUncontrolledDomainFallback` defaults to `false` and appears in configuration logging. The internal resolver attempts controlled LDAP first and permits legacy framework resolution only after core identity resolution fails and this flag is enabled. Fallback use is logged and may ignore LDAP settings. Successful controlled results with unavailable additional metadata never trigger legacy enrichment. The current public `GetDomain` signatures and behavior are unchanged, and this flag does not yet control those calls.

`LdapConfig.UserDomain` declares the DNS or NetBIOS domain associated with the user's credentials. The internal controlled resolver selects its endpoint in this order: `Server`, the supplied domain argument, `UserDomain`, then `USERDNSDOMAIN`. Null, empty, or whitespace hints are ignored. The resolved identity comes from LDAP; the hint does not restrict collection to the credential domain.

For `/netonly`, set `UserDomain` to the outbound credential domain and leave `Username` unset so LDAP binding uses ambient outbound credentials:

```csharp
var config = new LdapConfig {
    UserDomain = "child.example.test"
};
```

`UserDomain` defaults to null and appears in configuration logging. It guides endpoint selection without changing credentials or the Windows authentication context. As with the controlled resolver itself, this hint is not yet wired into the public `GetDomain` calls.

## Relationship to SharpHoundRPC

`SharpHoundCommon` depends on `SharpHoundRPC` and is intended to be the higher-level entry point. Most consumers should not reference `SharpHoundRPC` directly unless they need its lower-level SAM, LSA, NetAPI, or registry APIs.

## Source and support

- Source: https://github.com/SpecterOps/SharpHoundCommon
- Issues: https://github.com/SpecterOps/SharpHoundCommon/issues
- License: GPL-3.0-only

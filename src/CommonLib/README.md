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

All `GetDomain` overloads now return `LdapDomainInfo` through the synchronous `bool`/`out` pattern instead of framework `Domain` objects. Success requires a resolved name and default naming context. Callers should use the returned naming contexts and check optional metadata before using it. Successful controlled results are cached per `LdapUtils` instance, case-insensitively; `SetLdapConfig` and `ResetUtils` clear that cache. Static calls and legacy results are not cached.

`LdapConfig.AllowUncontrolledDomainFallback` defaults to `false` and appears in configuration logging. `GetDomain` attempts controlled LDAP first and permits legacy framework resolution only after core identity resolution fails and this flag is enabled. Fallback use is logged and may ignore LDAP settings. Successful controlled results with unavailable additional metadata never trigger legacy enrichment.

`LdapConfig.UserDomain` declares the DNS or NetBIOS domain associated with the user's credentials. The internal controlled resolver selects its endpoint in this order: `Server`, the supplied domain argument, `UserDomain`, then `USERDNSDOMAIN`. Null, empty, or whitespace hints are ignored. The resolved identity comes from LDAP; the hint does not restrict collection to the credential domain.

For reliable `/netonly` use, supply an explicit `Server` or domain argument to `GetDomain` and leave `Username` unset so LDAP binding can use ambient outbound credentials. For example, run the calling application under `runas /netonly` and resolve the target through the static overload:

```csharp
var config = new LdapConfig {
    Server = "dc.child.example.test",
    ForceSSL = true
};

if (LdapUtils.GetDomain("child.example.test", config, out var domain)) {
    // domain.Name and domain.DefaultNamingContext come from the target's LDAP response.
    var searchBase = domain.DefaultNamingContext;
}
```

`UserDomain` defaults to null and appears in configuration logging. It guides endpoint selection without changing credentials or the Windows authentication context. For reliable `/netonly` targeting, supply `Server` or a domain argument to `GetDomain`; `USERDNSDOMAIN` is only a last-resort target hint.

Controlled resolution tries SSL first, using `SSLPort` (default 636). An SSL operation failure permits a retry on the same endpoint using `Port` (default 389) only when `ForceSSL` is false. Invalid credentials or inappropriate authentication fail resolution without a transport retry. It preserves `AuthType`, enables signing and sealing on plaintext connections unless `DisableSigning` is set, and validates certificates unless `DisableCertVerification` is set. A configured `Username` supplies explicit credentials instead of ambient credentials.

With `Server` configured, every resolver read stays on that host with referrals and automatic reconnection disabled. Discovered PDC and controller names are returned as metadata. A supplied DNS domain or NetBIOS alias must match the target's advertised identity; a mismatch fails controlled resolution. Unavailable SID, PDC, controller, or trust metadata preserves successful core resolution without changing endpoints or invoking legacy enrichment.

## Relationship to SharpHoundRPC

`SharpHoundCommon` depends on `SharpHoundRPC` and is intended to be the higher-level entry point. Most consumers should not reference `SharpHoundRPC` directly unless they need its lower-level SAM, LSA, NetAPI, or registry APIs.

## Source and support

- Source: https://github.com/SpecterOps/SharpHoundCommon
- Issues: https://github.com/SpecterOps/SharpHoundCommon/issues
- License: GPL-3.0-only

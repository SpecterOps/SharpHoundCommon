using System;
using System.Collections.Generic;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.Models;

/// <summary>
/// Plain domain metadata with no framework directory objects or resources to dispose.
/// Successful resolution requires <see cref="Name"/> and <see cref="DefaultNamingContext"/>.
/// Unavailable additional strings are null and unavailable collections are empty.
/// </summary>
public class LdapDomainInfo {
    /// <summary>The resolved DNS domain name.</summary>
    public string Name { get; set; }

    /// <summary>The DNS forest name, or null when unavailable.</summary>
    public string ForestName { get; set; }

    /// <summary>The domain SID, or null when unavailable.</summary>
    public string DomainSid { get; set; }

    /// <summary>The distinguished name of the domain's default naming context.</summary>
    public string DefaultNamingContext { get; set; }

    /// <summary>The configuration naming context, or null when unavailable.</summary>
    public string ConfigurationNamingContext { get; set; }

    /// <summary>The schema naming context, or null when unavailable.</summary>
    public string SchemaNamingContext { get; set; }

    /// <summary>The PDC role owner's hostname, or null when unavailable.</summary>
    public string PdcRoleOwnerName { get; set; }

    /// <summary>Available domain controller hostnames; empty when unavailable.</summary>
    public List<string> DomainControllerNames { get; } = new();

    /// <summary>Trust classifications indexed by case-insensitive target domain name; empty when unavailable.</summary>
    public Dictionary<string, TrustType> TrustTypes { get; } = new(StringComparer.OrdinalIgnoreCase);
}

using System;
using System.Collections.Generic;

namespace SharpHoundCommonLib
{
    /// <summary>
    /// Lightweight, transport-agnostic description of an Active Directory domain populated either
    /// from controlled LDAP queries (honoring <see cref="LdapConfig"/>) or, when explicitly opted in
    /// via <see cref="LdapConfig.AllowFallbackToUncontrolledLdap"/>, from
    /// <c>System.DirectoryServices.ActiveDirectory.Domain.GetDomain</c>.
    /// </summary>
    public sealed class DomainInfo
    {
        /// <summary>Upper-cased DNS name of the domain (e.g. <c>CONTOSO.LOCAL</c>).</summary>
        public string Name { get; set; }

        /// <summary>Default naming context distinguished name (e.g. <c>DC=contoso,DC=local</c>).</summary>
        public string DistinguishedName { get; set; }

        /// <summary>Upper-cased DNS name of the forest root domain, when known.</summary>
        public string ForestName { get; set; }

        /// <summary>Domain SID (S-1-5-21-...) if resolved, otherwise null.</summary>
        public string DomainSid { get; set; }

        /// <summary>Legacy NetBIOS domain name if resolved from the Partitions container, otherwise null.</summary>
        public string NetBiosName { get; set; }

        /// <summary>DNS hostname of the PDC FSMO role owner if resolved, otherwise null.</summary>
        public string PrimaryDomainController { get; set; }

        /// <summary>DNS hostnames of known domain controllers for this domain.</summary>
        public IReadOnlyList<string> DomainControllers { get; set; } = Array.Empty<string>();
    }
}

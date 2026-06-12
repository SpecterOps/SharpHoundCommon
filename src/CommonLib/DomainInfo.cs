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
        public string Name { get; }

        /// <summary>Default naming context distinguished name (e.g. <c>DC=contoso,DC=local</c>).</summary>
        public string DistinguishedName { get; }

        /// <summary>Upper-cased DNS name of the forest root domain, when known.</summary>
        public string ForestName { get; }

        /// <summary>Domain SID (S-1-5-21-...) if resolved, otherwise null.</summary>
        public string DomainSid { get; }

        /// <summary>Legacy NetBIOS domain name if resolved from the Partitions container, otherwise null.</summary>
        public string NetBiosName { get; }

        /// <summary>DNS hostname of the PDC FSMO role owner if resolved, otherwise null.</summary>
        public string PrimaryDomainController { get; }

        /// <summary>DNS hostnames of known domain controllers for this domain.</summary>
        public IReadOnlyList<string> DomainControllers { get; }

        public DomainInfo(
            string name = null,
            string distinguishedName = null,
            string forestName = null,
            string domainSid = null,
            string netBiosName = null,
            string primaryDomainController = null,
            IReadOnlyList<string> domainControllers = null) {
            Name = name;
            DistinguishedName = distinguishedName;
            ForestName = forestName;
            DomainSid = domainSid;
            NetBiosName = netBiosName;
            PrimaryDomainController = primaryDomainController;
            DomainControllers = domainControllers ?? Array.Empty<string>();
        }

        /// <summary>
        /// Counts the populated fields on this instance as a coarse measure of how much information
        /// a particular domain resolution tier produced. <see cref="DomainControllers"/> is treated
        /// as populated only when non-empty because the constructor coalesces null to an empty array.
        /// </summary>
        internal int CompletenessScore() {
            var score = 0;
            if (!string.IsNullOrEmpty(Name)) score++;
            if (!string.IsNullOrEmpty(DistinguishedName)) score++;
            if (!string.IsNullOrEmpty(ForestName)) score++;
            if (!string.IsNullOrEmpty(DomainSid)) score++;
            if (!string.IsNullOrEmpty(NetBiosName)) score++;
            if (!string.IsNullOrEmpty(PrimaryDomainController)) score++;
            if (DomainControllers != null && DomainControllers.Count > 0) score++;
            return score;
        }
    }
}

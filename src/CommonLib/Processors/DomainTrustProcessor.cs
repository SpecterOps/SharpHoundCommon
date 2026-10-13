using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class DomainTrustProcessor
    {
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;

        public DomainTrustProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("DomainTrustProc");
        }

        /// <summary>
        ///     Processes domain trusts for a domain object
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<DomainTrust> EnumerateDomainTrusts(string domain)
        {
            _log.LogDebug("Running trust enumeration for {Domain}", domain);

            // Domain resolution enriches trust records with forest topology. A trustParent link
            // identifies ParentChild; a forest-root/alternate-root pair identifies TreeRoot;
            // other within-forest relationships are CrossLink. Missing topology leaves Unknown.
            var trustTypes = new Dictionary<string, TrustType>(System.StringComparer.OrdinalIgnoreCase);
            if (_utils.GetDomain(domain, out var domainInfo)) {
                trustTypes = domainInfo.TrustTypes;
            }

            await foreach (var result in _utils.Query(new LdapQueryParameters {
                                   LDAPFilter = CommonFilters.TrustedDomains,
                                   Attributes = CommonProperties.DomainTrustProps,
                                   DomainName = domain
                               }))
            {
                if (!result.IsSuccess) {
                    yield break;
                }

                var entry = result.Value;
                _log.LogDebug("Got Trust: {Trust}", entry.DumpDirectoryObject());
                var trust = new DomainTrust();
                if (!entry.TryGetByteProperty(LDAPProperties.SecurityIdentifier, out var targetSidBytes) || targetSidBytes.Length == 0) {
                    _log.LogDebug("Trust sid is null or empty for target: {Domain}", domain);
                    continue;
                }

                string sid;
                try
                {
                    sid = new SecurityIdentifier(targetSidBytes, 0).Value;
                }
                catch
                {
                    _log.LogTrace("Failed to convert bytes to SID for target: {Domain}", domain);
                    continue;
                }

                trust.TargetDomainSid = sid;

                if (!entry.TryGetLongProperty(LDAPProperties.TrustDirection, out var td)) {
                    _log.LogTrace("Failed to convert trustdirection for target: {Domain}", domain);
                    continue;
                }

                trust.TrustDirection = (TrustDirection) td;
                
                TrustAttributes attributes;

                if (!entry.TryGetLongProperty(LDAPProperties.TrustAttributes, out var ta)) {
                    _log.LogTrace("Failed to convert trustattributes for target: {Domain}", domain);
                    continue;
                }
                
                trust.TrustAttributes = ta;
                attributes = (TrustAttributes) ta;

                trust.IsTransitive = !attributes.HasFlag(TrustAttributes.NonTransitive);
                // The resolver keys classifications by trustPartner. Prefer the same target name
                // here so a differing cn does not lose enrichment; retain cn as a fallback.
                if (entry.TryGetProperty(LDAPProperties.TrustPartner, out var partner) &&
                    !string.IsNullOrWhiteSpace(partner)) {
                    trust.TargetDomainName = partner.Trim().ToUpperInvariant();
                }
                else if (entry.TryGetProperty(LDAPProperties.CanonicalName, out var cn)) {
                    trust.TargetDomainName = cn.ToUpperInvariant();
                }

                trust.SidFilteringEnabled = 
                    attributes.HasFlag(TrustAttributes.QuarantinedDomain) || 
                    (attributes.HasFlag(TrustAttributes.ForestTransitive) && 
                    !attributes.HasFlag(TrustAttributes.TreatAsExternal));

                trust.TGTDelegationEnabled = 
                    !attributes.HasFlag(TrustAttributes.QuarantinedDomain) &&
                    (attributes.HasFlag(TrustAttributes.WithinForest) ||
                    attributes.HasFlag(TrustAttributes.CrossOrganizationEnableTGTDelegation));

                // Preserve a known enriched classification. An absent or Unknown result can still
                // be classified from this entry's readable type and attributes without topology.
                if (trust.TargetDomainName != null && trustTypes.TryGetValue(trust.TargetDomainName, out var classifiedType) &&
                    classifiedType != TrustType.Unknown) {
                    trust.TrustType = classifiedType;
                }
                else {
                    var ldapTrustType = entry.TryGetLongProperty(LDAPProperties.TrustType, out var type)
                        ? type : (long?)null;
                    trust.TrustType = Classify(ldapTrustType, attributes);
                }

                yield return trust;
            }
        }

        // Shared by enumeration and the resolver, which supplies withinForestType from topology.
        internal static TrustType Classify(long? ldapTrustType, TrustAttributes? attributes,
            TrustType withinForestType = TrustType.Unknown)
        {
            // LDAP trustType is a protocol value, not our output enum: 3 means an MIT Kerberos
            // realm and takes precedence over attributes; 1 and 2 represent Windows domains.
            if (ldapTrustType == 3) return TrustType.Kerberos;
            // Missing or unsupported Windows trust fields cannot establish a classification.
            if ((ldapTrustType != 1 && ldapTrustType != 2) || !attributes.HasValue) return TrustType.Unknown;
            // WithinForest alone cannot distinguish ParentChild, TreeRoot, and CrossLink.
            // Without the resolver's topology classification, keep the default Unknown.
            if (attributes.Value.HasFlag(TrustAttributes.WithinForest)) return withinForestType;
            // TreatAsExternal affects SID filtering, not the Forest classification.
            return attributes.Value.HasFlag(TrustAttributes.ForestTransitive) ? TrustType.Forest : TrustType.External;
        }
    }
}

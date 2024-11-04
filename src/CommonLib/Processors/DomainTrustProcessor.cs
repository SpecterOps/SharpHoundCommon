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
                if (entry.TryGetProperty(LDAPProperties.CanonicalName, out var cn)) {
                    trust.TargetDomainName = cn.ToUpper();
                }

                trust.SidFilteringEnabled = 
                    attributes.HasFlag(TrustAttributes.QuarantinedDomain) || 
                    (attributes.HasFlag(TrustAttributes.ForestTransitive) && 
                    !attributes.HasFlag(TrustAttributes.TreatAsExternal));

                trust.TGTDelegationEnabled = 
                    !attributes.HasFlag(TrustAttributes.QuarantinedDomain) &&
                    (attributes.HasFlag(TrustAttributes.WithinForest) ||
                    attributes.HasFlag(TrustAttributes.CrossOrganizationEnableTGTDelegation));

                trust.TrustType = TrustAttributesToType(attributes);

                yield return trust;
            }
        }

        public static TrustType TrustAttributesToType(TrustAttributes attributes)
        {
            TrustType trustType;

            if (attributes.HasFlag(TrustAttributes.WithinForest))
                trustType = TrustType.ParentChild;
            else if (attributes.HasFlag(TrustAttributes.ForestTransitive))
                trustType = TrustType.Forest;
            else if (!attributes.HasFlag(TrustAttributes.WithinForest) &&
                     !attributes.HasFlag(TrustAttributes.ForestTransitive))
                trustType = TrustType.External;
            else
                trustType = TrustType.Unknown;

            return trustType;
        }
    }
}

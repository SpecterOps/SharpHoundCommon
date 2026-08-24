using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib {
    public partial class LdapUtils {
        public async Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain) {
            if (Cache.GetGCCache(name, out var matches)) {
                return (true, matches);
            }

            var sids = new List<string>();

            await foreach (var result in Query(new LdapQueryParameters {
                DomainName = domain,
                Attributes = new[] { LDAPProperties.ObjectSID },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddUsers($"(samaccountname={name})").GetFilter()
            })) {
                if (result.IsSuccess && result.Value.TryGetSecurityIdentifier(out var sid)) {
                    if (await GetWellKnownPrincipal(sid, domain) is (true, var principal)) {
                        sids.Add(principal.ObjectIdentifier);
                    }
                    else {
                        sids.Add(sid);
                    }
                }
                else {
                    return (false, Array.Empty<string>());
                }
            }

            Cache.AddGCCache(name, sids.ToArray());
            return (true, sids.ToArray());
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(string propertyValue,
            string propertyName, string domainName) {
            var filter = new LdapFilter().AddCertificateTemplates()
                .AddFilter($"({propertyName}={propertyValue})", true);
            var result = await Query(new LdapQueryParameters {
                DomainName = domainName,
                Attributes = CommonProperties.TypeResolutionProps,
                SearchScope = SearchScope.OneLevel,
                NamingContext = NamingContext.Configuration,
                RelativeSearchBase = DirectoryPaths.CertTemplateLocation,
                LDAPFilter = filter.GetFilter(),
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (!result.IsSuccess) {
                _log.LogWarning(
                    "Could not find certificate template with {PropertyName}:{PropertyValue}: {Error}",
                    propertyName, propertyValue, result.Error);
                return (false, null);
            }

            if (result.Value.TryGetGuid(out var guid)) {
                return (true, new TypedPrincipal(guid, Label.CertTemplate));
            }

            return (false, default);
        }

        public async Task<(bool Success, string DSHeuristics)> GetDSHueristics(string domain, string dn) {
            var configPath = CommonPaths.CreateDNPath(CommonPaths.DirectoryServicePath, dn);
            var queryParameters = new LdapQueryParameters {
                Attributes = new[] { LDAPProperties.DSHeuristics },
                SearchScope = SearchScope.Base,
                DomainName = domain,
                LDAPFilter = new LdapFilter().AddAllObjects().GetFilter(),
                NamingContext = NamingContext.Configuration,
                SearchBase = configPath
            };

            var result = await Query(queryParameters).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail())
                .FirstOrDefaultAsync();
            if (result.IsSuccess &&
                result.Value.TryGetProperty(LDAPProperties.DSHeuristics, out var dsh)) {
                return (true, dsh);
            }

            return (false, null);
        }

    }
}

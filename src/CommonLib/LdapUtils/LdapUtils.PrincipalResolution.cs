using System;
using System.Collections.Concurrent;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Static;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib {
    public partial class LdapUtils {
        private static ConcurrentHashSet _unresolvablePrincipals = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, TypedPrincipal> _distinguishedNameCache =
            new(StringComparer.OrdinalIgnoreCase);

        // Metrics
        private readonly IMetricRouter _metric;
        private static readonly Regex SIDRegex = new(@"^(S-\d+-\d+-\d+-\d+-\d+-\d+)(-\d+)?$");

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(
            SecurityIdentifier securityIdentifier,
            string objectDomain) {
            return await ResolveIDAndType(securityIdentifier.Value, objectDomain);
        }

        public async Task<(bool Success, TypedPrincipal Principal)>
            ResolveIDAndType(string identifier, string objectDomain) {
            if (identifier.IndexOf("0ACNF", StringComparison.OrdinalIgnoreCase) >= 0) {
                return (false, new TypedPrincipal(identifier, Label.Base));
            }

            if (await GetWellKnownPrincipal(identifier, objectDomain) is (true, var principal)) {
                return (true, principal);
            }

            if (_unresolvablePrincipals.Contains(identifier)) {
                return (false, new TypedPrincipal(identifier, Label.Base));
            }

            if (identifier.StartsWith("S-")) {
                var result = await LookupSidType(identifier, objectDomain);
                if (!result.Success) {
                    _unresolvablePrincipals.Add(identifier);
                    _metric.Observe(LdapMetricDefinitions.UnresolvablePrincipals, 1, new LabelValues([nameof(LdapUtils)]));
                }

                return (result.Success, new TypedPrincipal(identifier, result.Type));
            }

            var (success, type) = await LookupGuidType(identifier, objectDomain);
            if (!success) {
                _unresolvablePrincipals.Add(identifier);
                _metric.Observe(LdapMetricDefinitions.UnresolvablePrincipals, 1, new LabelValues([nameof(LdapUtils)]));
            }

            return (success, new TypedPrincipal(identifier, type));
        }

        private async Task<(bool Success, Label Type)> LookupSidType(string sid, string domain) {
            if (Cache.GetIDType(sid, out var type)) {
                return (true, type);
            }

            var tempDomain = domain;

            if (await GetDomainNameFromSid(sid) is (true, var domainName)) {
                tempDomain = domainName;
            }

            var result = await Query(new LdapQueryParameters() {
                DomainName = tempDomain,
                LDAPFilter = CommonFilters.SpecificSID(sid),
                Attributes = CommonProperties.TypeResolutionProps
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess) {
                if (result.Value.GetLabel(out type)) {
                    Cache.AddType(sid, type);
                    return (true, type);
                }
            }

            try {
                var entry = CreateDirectoryEntry($"LDAP://<SID={sid}>");
                if (entry.GetLabel(out type)) {
                    Cache.AddType(sid, type);
                    return (true, type);
                }
            }
            catch {
                //pass
            }

            try {
                using (var ctx = new PrincipalContext(ContextType.Domain)) {
                    // Blocking External Call
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                    if (principal != null) {
                        // Blocking External Call
                        var entry = ((DirectoryEntry)principal.GetUnderlyingObject()).ToDirectoryObject();
                        if (entry.GetLabel(out type)) {
                            Cache.AddType(sid, type);
                            return (true, type);
                        }
                    }
                }
            }
            catch {
                //pass
            }


            return (false, Label.Base);
        }

        private async Task<(bool Success, Label type)> LookupGuidType(string guid, string domain) {
            if (Cache.GetIDType(guid, out var type)) {
                return (true, type);
            }

            var result = await Query(new LdapQueryParameters() {
                DomainName = domain,
                LDAPFilter = CommonFilters.SpecificGUID(guid),
                Attributes = CommonProperties.TypeResolutionProps
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.GetLabel(out type)) {
                Cache.AddType(guid, type);
                return (true, type);
            }

            try {
                var entry = CreateDirectoryEntry($"LDAP://<GUID={guid}>");
                if (entry.GetLabel(out type)) {
                    Cache.AddType(guid, type);
                    return (true, type);
                }
            }
            catch {
                //pass
            }

            try {
                using (var ctx = new PrincipalContext(ContextType.Domain)) {
                    // Blocking External Call
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Guid, guid);
                    if (principal != null) {
                        // Blocking External Call
                        var entry = ((DirectoryEntry)principal.GetUnderlyingObject()).ToDirectoryObject();
                        if (entry.GetLabel(out type)) {
                            Cache.AddType(guid, type);
                            return (true, type);
                        }
                    }
                }
            }
            catch {
                //pass
            }


            return (false, Label.Base);
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain) {
            if (string.IsNullOrWhiteSpace(name)) {
                return (false, null);
            }

            if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetIDType(id, out var type))
                return (true, new TypedPrincipal {
                    ObjectIdentifier = id,
                    ObjectType = type
                });

            var result = await Query(new LdapQueryParameters() {
                DomainName = domain,
                Attributes = CommonProperties.TypeResolutionProps,
                LDAPFilter = $"(samaccountname={name})"
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.GetObjectIdentifier(out id)) {
                result.Value.GetLabel(out type);
                Cache.AddPrefixedValue(name, domain, id);
                Cache.AddType(id, type);

                var (tempID, _) = await GetWellKnownPrincipalObjectIdentifier(id, domain);
                return (true, new TypedPrincipal(tempID, type));
            }

            return (false, null);
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveDistinguishedName(string distinguishedName) {
            if (_distinguishedNameCache.TryGetValue(distinguishedName, out var principal)) {
                return (true, principal);
            }

            if (_unresolvablePrincipals.Contains(distinguishedName)) {
                return (false, default);
            }

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var result = await Query(new LdapQueryParameters {
                DomainName = domain,
                Attributes = CommonProperties.TypeResolutionProps,
                SearchBase = distinguishedName,
                SearchScope = SearchScope.Base,
                LDAPFilter = new LdapFilter().AddAllObjects().GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.GetObjectIdentifier(out var id)) {
                var entry = result.Value;

                if (await GetWellKnownPrincipal(id, domain) is (true, var wellKnownPrincipal)) {
                    _distinguishedNameCache.TryAdd(distinguishedName, wellKnownPrincipal);
                    return (true, wellKnownPrincipal);
                }

                entry.GetLabel(out var type);
                principal = new TypedPrincipal(id, type);
                _distinguishedNameCache.TryAdd(distinguishedName, principal);
                return (true, principal);
            }

            try {
                using (var ctx = new PrincipalContext(ContextType.Domain)) {
                    // Blocking External Call
                    var lookupPrincipal =
                        Principal.FindByIdentity(ctx, IdentityType.DistinguishedName, distinguishedName);
                    if (lookupPrincipal != null) {
                        // Blocking External Call
                        var entry = ((DirectoryEntry)lookupPrincipal.GetUnderlyingObject()).ToDirectoryObject();
                        if (entry.GetObjectIdentifier(out var identifier) && entry.GetLabel(out var label)) {
                            if (await GetWellKnownPrincipal(identifier, domain) is (true, var wellKnownPrincipal)) {
                                _distinguishedNameCache.TryAdd(distinguishedName, wellKnownPrincipal);
                                return (true, wellKnownPrincipal);
                            }

                            principal = new TypedPrincipal(identifier, label);
                            _distinguishedNameCache.TryAdd(distinguishedName, principal);
                            return (true, new TypedPrincipal(identifier, label));
                        }
                    }

                    return (false, default);
                }
            }
            catch {
                _unresolvablePrincipals.Add(distinguishedName);
                _metric.Observe(LdapMetricDefinitions.UnresolvablePrincipals, 1, new LabelValues([nameof(LdapUtils)]));
                return (false, default);
            }
        }

    }
}

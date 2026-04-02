using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Static;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib;

/// <summary>
/// Resolves principal identifiers (SIDs, GUIDs, DNs, account names) to typed BloodHound principals.
/// Extracted from LdapUtils to give principal resolution a single, focused home.
///
/// Dependencies flow through ILdapUtils so that Moq-based test overrides of virtual methods
/// (GetDomainNameFromSid, GetWellKnownPrincipal, Query, etc.) continue to work.
/// </summary>
internal class PrincipalResolver {
    // Static so the "already failed to resolve" set is shared across instances (same as original).
    private static ConcurrentHashSet _unresolvablePrincipals = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, TypedPrincipal> _distinguishedNameCache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ILdapUtils _utils;
    private readonly WellKnownPrincipalService _wkpService;
    private readonly DomainControllerRegistry _dcRegistry;
    private LdapConfig _ldapConfig;
    private readonly ILogger _log;
    private readonly IMetricRouter _metric;

    internal PrincipalResolver(ILdapUtils utils, WellKnownPrincipalService wkpService,
        DomainControllerRegistry dcRegistry, LdapConfig ldapConfig, ILogger log, IMetricRouter metric) {
        _utils = utils;
        _wkpService = wkpService;
        _dcRegistry = dcRegistry;
        _ldapConfig = ldapConfig;
        _log = log;
        _metric = metric;
    }

    /// <summary>Called by LdapUtils.SetLdapConfig to keep credentials in sync.</summary>
    internal void UpdateConfig(LdapConfig config) => _ldapConfig = config;

    /// <summary>Resets transient state. Called by LdapUtils.ResetUtils for test isolation.</summary>
    internal void Reset() {
        _unresolvablePrincipals = new ConcurrentHashSet(StringComparer.OrdinalIgnoreCase);
        _distinguishedNameCache.Clear();
    }

    internal async Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(
        string identifier, string objectDomain) {
        if (identifier.IndexOf("0ACNF", StringComparison.OrdinalIgnoreCase) >= 0) {
            return (false, new TypedPrincipal(identifier, Label.Base));
        }

        if (await _utils.GetWellKnownPrincipal(identifier, objectDomain) is (true, var principal)) {
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
        if (await _utils.GetDomainNameFromSid(sid) is (true, var domainName)) {
            tempDomain = domainName;
        }

        var result = await _utils.Query(new LdapQueryParameters() {
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
            using var ctx = new PrincipalContext(ContextType.Domain);
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
        catch {
            //pass
        }

        return (false, Label.Base);
    }

    private async Task<(bool Success, Label type)> LookupGuidType(string guid, string domain) {
        if (Cache.GetIDType(guid, out var type)) {
            return (true, type);
        }

        var result = await _utils.Query(new LdapQueryParameters() {
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
            using var ctx = new PrincipalContext(ContextType.Domain);
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
        catch {
            //pass
        }

        return (false, Label.Base);
    }

    internal async Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain) {
        if (string.IsNullOrWhiteSpace(name)) {
            return (false, null);
        }

        if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetIDType(id, out var type))
            return (true, new TypedPrincipal { ObjectIdentifier = id, ObjectType = type });

        var result = await _utils.Query(new LdapQueryParameters() {
            DomainName = domain,
            Attributes = CommonProperties.TypeResolutionProps,
            LDAPFilter = $"(samaccountname={name})"
        }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

        if (result.IsSuccess && result.Value.GetObjectIdentifier(out id)) {
            result.Value.GetLabel(out type);
            Cache.AddPrefixedValue(name, domain, id);
            Cache.AddType(id, type);

            var (tempID, _) = await _wkpService.GetWellKnownPrincipalObjectIdentifier(id, domain);
            return (true, new TypedPrincipal(tempID, type));
        }

        return (false, null);
    }

    internal async Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain) {
        if (Cache.GetGCCache(name, out var matches)) {
            return (true, matches);
        }

        var sids = new System.Collections.Generic.List<string>();

        await foreach (var result in _utils.Query(new LdapQueryParameters {
            DomainName = domain,
            Attributes = new[] { LDAPProperties.ObjectSID },
            GlobalCatalog = true,
            LDAPFilter = new LdapFilter().AddUsers($"(samaccountname={name})").GetFilter()
        })) {
            if (result.IsSuccess && result.Value.TryGetSecurityIdentifier(out var sid)) {
                if (await _utils.GetWellKnownPrincipal(sid, domain) is (true, var principal)) {
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

    internal async Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(
        string propertyValue, string propertyName, string domainName) {
        var filter = new LdapFilter().AddCertificateTemplates()
            .AddFilter($"({propertyName}={propertyValue})", true);
        var result = await _utils.Query(new LdapQueryParameters {
            DomainName = domainName,
            Attributes = CommonProperties.TypeResolutionProps,
            SearchScope = SearchScope.OneLevel,
            NamingContext = NamingContext.Configuration,
            RelativeSearchBase = DirectoryPaths.CertTemplateLocation,
            LDAPFilter = filter.GetFilter(),
        }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

        if (!result.IsSuccess) {
            _log.LogWarning("Could not find certificate template with {PropertyName}:{PropertyValue}: {Error}",
                propertyName, propertyValue, result.Error);
            return (false, null);
        }

        if (result.Value.TryGetGuid(out var guid)) {
            return (true, new TypedPrincipal(guid, Label.CertTemplate));
        }

        return (false, default);
    }

    internal async Task<(bool Success, TypedPrincipal Principal)> ResolveDistinguishedName(
        string distinguishedName) {
        if (_distinguishedNameCache.TryGetValue(distinguishedName, out var principal)) {
            return (true, principal);
        }

        if (_unresolvablePrincipals.Contains(distinguishedName)) {
            return (false, default);
        }

        var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
        var result = await _utils.Query(new LdapQueryParameters {
            DomainName = domain,
            Attributes = CommonProperties.TypeResolutionProps,
            SearchBase = distinguishedName,
            SearchScope = SearchScope.Base,
            LDAPFilter = new LdapFilter().AddAllObjects().GetFilter()
        }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

        if (result.IsSuccess && result.Value.GetObjectIdentifier(out var id)) {
            var entry = result.Value;

            if (await _utils.GetWellKnownPrincipal(id, domain) is (true, var wellKnownPrincipal)) {
                _distinguishedNameCache.TryAdd(distinguishedName, wellKnownPrincipal);
                return (true, wellKnownPrincipal);
            }

            entry.GetLabel(out var type);
            principal = new TypedPrincipal(id, type);
            _distinguishedNameCache.TryAdd(distinguishedName, principal);
            return (true, principal);
        }

        try {
            using var ctx = new PrincipalContext(ContextType.Domain);
            // Blocking External Call
            var lookupPrincipal =
                Principal.FindByIdentity(ctx, IdentityType.DistinguishedName, distinguishedName);
            if (lookupPrincipal != null) {
                // Blocking External Call
                var entry = ((DirectoryEntry)lookupPrincipal.GetUnderlyingObject()).ToDirectoryObject();
                if (entry.GetObjectIdentifier(out var identifier) && entry.GetLabel(out var label)) {
                    if (await _utils.GetWellKnownPrincipal(identifier, domain) is (true, var wellKnownPrincipal)) {
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
        catch {
            _unresolvablePrincipals.Add(distinguishedName);
            _metric.Observe(LdapMetricDefinitions.UnresolvablePrincipals, 1, new LabelValues([nameof(LdapUtils)]));
            return (false, default);
        }
    }

    internal async Task<bool> IsDomainController(string computerObjectId, string domainName) {
        if (_dcRegistry.Contains(computerObjectId)) {
            return true;
        }

        var resDomain = await _utils.GetDomainNameFromSid(domainName) is (false, var tempDomain)
            ? tempDomain
            : domainName;
        var filter = new LdapFilter().AddFilter(CommonFilters.SpecificSID(computerObjectId), true)
            .AddFilter(CommonFilters.DomainControllers, true);
        var result = await _utils.Query(new LdapQueryParameters() {
            DomainName = resDomain,
            Attributes = CommonProperties.ObjectID,
            LDAPFilter = filter.GetFilter(),
        }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

        if (result.IsSuccess) {
            _dcRegistry.Add(computerObjectId);
        }

        return result.IsSuccess;
    }

    internal void AddDomainController(string domainControllerSID) {
        _dcRegistry.Add(domainControllerSID);
    }

    private IDirectoryObject CreateDirectoryEntry(string path) {
        if (_ldapConfig.Username != null) {
            return new DirectoryEntry(path, _ldapConfig.Username, _ldapConfig.Password).ToDirectoryObject();
        }

        return new DirectoryEntry(path).ToDirectoryObject();
    }
}

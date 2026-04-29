using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.Static;
using SharpHoundRPC.NetAPINative;
using SharpHoundRPC.PortScanner;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using Group = SharpHoundCommonLib.OutputTypes.Group;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib {
    public class LdapUtils : ILdapUtils {
        private static ConcurrentDictionary<string, DomainInfo> _domainInfoCache =
            new(StringComparer.OrdinalIgnoreCase);
        private static ConcurrentHashSet _domainControllers = new(StringComparer.OrdinalIgnoreCase);
        private static ConcurrentHashSet _unresolvablePrincipals = new(StringComparer.OrdinalIgnoreCase);

        // Coalesces concurrent first-time domain resolutions issued through the instance
        // GetDomainInfoAsync path so N callers asking for the same domain trigger one pool-driven
        // tier walk instead of N. Only the coalesced (pool-equipped) path inserts here; the
        // direct GetDomainInfoStaticAsync entry bypasses this dictionary entirely so the pool
        // tier can re-enter for SID/DN resolution without self-deadlocking on the outer Lazy.
        // Entries are removed once the task settles, so a later cache miss for the same domain
        // (e.g., post-ResetUtils) starts a fresh resolution rather than reusing a completed task.
        private static readonly ConcurrentDictionary<string, Lazy<Task<(bool Success, DomainInfo DomainInfo)>>>
            _inFlightDomainResolutions = new(StringComparer.OrdinalIgnoreCase);

        private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal>
            SeenWellKnownPrincipals = new();

        private static readonly AdaptiveTimeout _requestNetBiosNameAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(1), Logging.LogProvider.CreateLogger(nameof(RequestNETBIOSNameFromComputerAsync)));

        private static readonly AdaptiveTimeout _callNetWkstaGetInfoAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger(nameof(NativeMethods.CallNetWkstaGetInfo)));

        private readonly ConcurrentDictionary<string, string>
            _hostResolutionMap = new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, TypedPrincipal> _distinguishedNameCache =
            new(StringComparer.OrdinalIgnoreCase);

        // Metrics
        private readonly IMetricRouter _metric;

        private readonly ILogger _log;
        private readonly IPortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;

        // Per-instance cache for the no-hint Domain resolution. The OS-side resolution depends
        // on the calling thread's auth context and/or _ldapConfig credentials, neither of which
        // is a usable cache key for a process-wide store. Failures are not cached; the next call
        // retries.
        private Domain _currentDomain;
        private readonly object _currentDomainLock = new();
        private static readonly Regex SIDRegex = new(@"^(S-\d+-\d+-\d+-\d+-\d+-\d+)(-\d+)?$");

        private readonly string[] _translateNames = { "Administrator", "admin" };
        private LdapConfig _ldapConfig = new();

        private ConnectionPoolManager _connectionPool;

        private static readonly byte[] NameRequest = {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };

        private class ResolvedWellKnownPrincipal {
            public string DomainName { get; set; }
            public string WkpId { get; set; }
        }

        public LdapUtils() {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
            _metric = Metrics.Factory.CreateMetricRouter();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, _log);
        }

        public LdapUtils(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null, IMetricRouter metric = null) {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
            _metric = metric ?? Metrics.Factory.CreateMetricRouter();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
        }

        public IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
            string attributeName, CancellationToken cancellationToken = new()) {
            return _connectionPool.RangedRetrieval(distinguishedName, attributeName, cancellationToken);
        }

        public IAsyncEnumerable<LdapResult<IDirectoryObject>> Query(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new()) {
            return _connectionPool.Query(queryParameters, cancellationToken);
        }

        public IAsyncEnumerable<LdapResult<IDirectoryObject>> PagedQuery(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new()) {
            return _connectionPool.PagedQuery(queryParameters, cancellationToken);
        }

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
                var entry = Helpers.CreateDirectoryEntry($"LDAP://<SID={sid}>", _ldapConfig);
                if (entry.GetLabel(out type)) {
                    Cache.AddType(sid, type);
                    return (true, type);
                }
            }
            catch {
                //pass
            }

            try {
                using (var ctx = CreatePrincipalContext(_ldapConfig, tempDomain)) {
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
                var entry = Helpers.CreateDirectoryEntry($"LDAP://<GUID={guid}>", _ldapConfig);
                if (entry.GetLabel(out type)) {
                    Cache.AddType(guid, type);
                    return (true, type);
                }
            }
            catch {
                //pass
            }

            try {
                using (var ctx = CreatePrincipalContext(_ldapConfig, domain)) {
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

        public async Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
            string securityIdentifier, string objectDomain) {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out var wellKnownPrincipal)) {
                return (false, null);
            }

            var (newIdentifier, newDomain) =
                await GetWellKnownPrincipalObjectIdentifier(securityIdentifier, objectDomain);

            wellKnownPrincipal.ObjectIdentifier = newIdentifier;
            SeenWellKnownPrincipals.TryAdd(wellKnownPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal {
                DomainName = newDomain,
                WkpId = securityIdentifier
            });

            return (true, wellKnownPrincipal);
        }

        private async Task<(string ObjectID, string Domain)> GetWellKnownPrincipalObjectIdentifier(
            string securityIdentifier, string domain) {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out _))
                return (securityIdentifier, string.Empty);

            if (!securityIdentifier.Equals("S-1-5-9", StringComparison.OrdinalIgnoreCase)) {
                var tempDomain = domain;
                if (await GetDomainInfoAsync(tempDomain) is (true, var domainInfo) &&
                    !string.IsNullOrEmpty(domainInfo?.Name)) {
                    tempDomain = domainInfo.Name;
                }

                return ($"{tempDomain}-{securityIdentifier}".ToUpper(), tempDomain);
            }

            if (await GetForest(domain) is (true, var forest)) {
                return ($"{forest}-{securityIdentifier}".ToUpper(), forest);
            }

            _log.LogWarning("Failed to get a forest name for domain {Domain}, unable to resolve enterprise DC sid",
                domain);
            return ($"UNKNOWN-{securityIdentifier}", "UNKNOWN");
        }

        public virtual async Task<(bool Success, string ForestName)> GetForest(string domain) {
            // DomainInfo.ForestName is already memoized in _domainInfoCache, so a separate
            // domain-to-forest dictionary would be a duplicate cache over the same key space.
            if (await GetDomainInfoAsync(domain) is (true, var domainInfo) &&
                !string.IsNullOrEmpty(domainInfo?.ForestName)) {
                return (true, domainInfo.ForestName);
            }

            return await GetForestFromLdap(domain);
        }

        private async Task<(bool Success, string ForestName)> GetForestFromLdap(string domain) {
            var queryParameters = new LdapQueryParameters {
                Attributes = new[] { LDAPProperties.RootDomainNamingContext },
                SearchScope = SearchScope.Base,
                DomainName = domain,
                LDAPFilter = new LdapFilter().AddAllObjects().GetFilter(),
            };

            var result = await Query(queryParameters).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail())
                .FirstOrDefaultAsync();
            if (result.IsSuccess &&
                result.Value.TryGetProperty(LDAPProperties.RootDomainNamingContext, out var rootNamingContext)) {
                return (true, Helpers.DistinguishedNameToDomain(rootNamingContext).ToUpper());
            }

            return (false, null);
        }

        public virtual async Task<(bool Success, string DomainName)> GetDomainNameFromSid(string sid) {
            string domainSid;
            try {
                domainSid = new SecurityIdentifier(sid).AccountDomainSid?.Value.ToUpper();
            }
            catch {
                var match = SIDRegex.Match(sid);
                domainSid = match.Success ? match.Groups[1].Value : null;
            }

            if (domainSid == null) {
                return (false, "");
            }

            if (Cache.GetDomainSidMapping(domainSid, out var domain)) {
                return (true, domain);
            }

            try {
                var entry = Helpers.CreateDirectoryEntry($"LDAP://<SID={domainSid}>", _ldapConfig);
                if (entry.TryGetDistinguishedName(out var dn)) {
                    Cache.AddDomainSidMapping(domainSid, Helpers.DistinguishedNameToDomain(dn));
                    return (true, Helpers.DistinguishedNameToDomain(dn));
                }
            }
            catch {
                //pass
            }

            if (await ConvertDomainSidToDomainNameFromLdap(sid) is (true, var domainName)) {
                Cache.AddDomainSidMapping(domainSid, domainName);
                return (true, domainName);
            }

            try {
                using (var ctx = CreatePrincipalContext(_ldapConfig)) {
                    // Blocking External Call
                    var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                    if (principal != null) {
                        var dn = principal.DistinguishedName;
                        if (!string.IsNullOrWhiteSpace(dn)) {
                            Cache.AddDomainSidMapping(domainSid, Helpers.DistinguishedNameToDomain(dn));
                            return (true, Helpers.DistinguishedNameToDomain(dn));
                        }
                    }
                }
            }
            catch {
                //pass
            }


            return (false, string.Empty);
        }

        private async Task<(bool Success, string DomainName)> ConvertDomainSidToDomainNameFromLdap(string domainSid) {
            var (domainOk, domainInfo) = await GetDomainInfoAsync();
            if (!domainOk || string.IsNullOrEmpty(domainInfo?.Name)) {
                return (false, string.Empty);
            }

            var result = await Query(new LdapQueryParameters {
                DomainName = domainInfo.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddDomains(CommonFilters.SpecificSID(domainSid)).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetDistinguishedName(out var distinguishedName)) {
                return (true, Helpers.DistinguishedNameToDomain(distinguishedName));
            }

            result = await Query(new LdapQueryParameters {
                DomainName = domainInfo.ForestName,
                Attributes = new[] { LDAPProperties.DistinguishedName, LDAPProperties.Name },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddFilter("(objectclass=trusteddomain)", true)
                    .AddFilter($"(securityidentifier={Helpers.ConvertSidToHexSid(domainSid)})", true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetProperty(LDAPProperties.Name, out var domainName)) {
                return (true, domainName.ToUpper());
            }

            result = await Query(new LdapQueryParameters {
                DomainName = domainInfo.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                LDAPFilter = new LdapFilter().AddFilter("(objectclass=domaindns)", true)
                    .AddFilter(CommonFilters.SpecificSID(domainSid), true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetDistinguishedName(out distinguishedName)) {
                return (true, Helpers.DistinguishedNameToDomain(distinguishedName));
            }

            return (false, string.Empty);
        }

        public virtual async Task<(bool Success, string DomainSid)> GetDomainSidFromDomainName(string domainName) {
            if (Cache.GetDomainSidMapping(domainName, out var domainSid)) return (true, domainSid);
            
            // Replaces the legacy GetDomain(out Domain) + GetDirectoryEntry block with a
            // controlled lookup via the connection pool.
            if (await GetDomainInfoAsync(domainName) is (true, var domainInfo) &&
                !string.IsNullOrEmpty(domainInfo?.DomainSid)) {
                Cache.AddDomainSidMapping(domainName, domainInfo.DomainSid);
                // Also seed the canonical FQDN keyed write so the SID->Name slot is populated
                // even when the caller passed a NetBIOS alias. AddDomainSidMapping gates the
                // SID->Name direction on the name being DNS-shaped, so the NetBIOS-keyed call
                // above only writes Name->SID; this second call fills in the FQDN side.
                if (!string.IsNullOrEmpty(domainInfo.Name) &&
                    !string.Equals(domainName, domainInfo.Name, StringComparison.OrdinalIgnoreCase)) {
                    Cache.AddDomainSidMapping(domainInfo.Name, domainInfo.DomainSid);
                }
                return (true, domainInfo.DomainSid);
            }

            try {
                var entry = Helpers.CreateDirectoryEntry($"LDAP://{domainName}", _ldapConfig);
                //Force load objectsid into the object cache
                if (entry.TryGetSecurityIdentifier(out var sid)) {
                    Cache.AddDomainSidMapping(domainName, sid);
                    domainSid = sid;
                    return (true, domainSid);
                }
            }
            catch {
                //we expect this to fail sometimes
            }
            
            foreach (var name in _translateNames)
                try {
                    var account = new NTAccount(domainName, name);
                    var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    domainSid = sid.AccountDomainSid.ToString().ToUpper();
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return (true, domainSid);
                }
                catch {
                    //We expect this to fail if the username doesn't exist in the domain
                }

            var result = await Query(new LdapQueryParameters() {
                DomainName = domainName,
                Attributes = new[] { LDAPProperties.ObjectSID },
                LDAPFilter = new LdapFilter().AddFilter(CommonFilters.DomainControllers, true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetSecurityIdentifier(out var securityIdentifier)) {
                domainSid = new SecurityIdentifier(securityIdentifier).AccountDomainSid.Value.ToUpper();
                Cache.AddDomainSidMapping(domainName, domainSid);
                return (true, domainSid);
            }

            return (false, string.Empty);
        }

        /// <summary>
        ///     Attempts to get the Domain object representing the target domain. If null is specified for the domain name, gets
        ///     the user's current domain
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public bool GetDomain(string domainName, out Domain domain) {
            if (!_ldapConfig.AllowFallbackToUncontrolledLdap) {
                _log.LogDebug(
                    "GetDomain(\"{Name}\", out Domain) short-circuited: AllowFallbackToUncontrolledLdap is disabled",
                    domainName);
                domain = null;
                return false;
            }

            if (!string.IsNullOrWhiteSpace(_ldapConfig.Server)) {
                _log.LogDebug(
                    "GetDomain(\"{Name}\", out Domain) short-circuited: Specific Server is set",
                    domainName);
                domain = null;
                return false;
            }

            // A blank/whitespace name is the no-target form. Delegate so the per-instance
            // _currentDomain handles it.
            if (string.IsNullOrWhiteSpace(domainName)) {
                return GetDomain(out domain);
            }

            try {
                var context = _ldapConfig.Username != null
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                        _ldapConfig.Password)
                    : new DirectoryContext(DirectoryContextType.Domain, domainName);

                // Blocking External Call
                domain = Domain.GetDomain(context);
                return domain != null;
            }
            catch (Exception e) {
                _log.LogDebug(e, "GetDomain call failed for domain name {Name}", domainName);
                domain = null;
                return false;
            }
        }

        public static bool GetDomain(string domainName, LdapConfig ldapConfig, out Domain domain) {
            if (ldapConfig is not { AllowFallbackToUncontrolledLdap: true }) {
                Logging.Logger.LogDebug(
                    "Static GetDomain(\"{DomainName}\") short-circuited: AllowFallbackToUncontrolledLdap is disabled",
                    domainName);
                domain = null;
                return false;
            }

            if (!string.IsNullOrWhiteSpace(ldapConfig.Server)) {
                Logging.Logger.LogDebug(
                    "Static GetDomain(\"{Name}\", out Domain) short-circuited: Specific Server is set",
                    domainName);
                domain = null;
                return false;
            }

            // The static overload has no per-instance state to anchor a no-hint resolution to.
            // Reject up front rather than proceeding with a resolution we can't attribute.
            if (string.IsNullOrWhiteSpace(domainName)) {
                Logging.Logger.LogDebug(
                    "Static GetDomain short-circuited: domainName is null or whitespace");
                domain = null;
                return false;
            }

            try {
                var context = ldapConfig.Username != null
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName, ldapConfig.Username,
                        ldapConfig.Password)
                    : new DirectoryContext(DirectoryContextType.Domain, domainName);

                // Blocking External Call
                domain = Domain.GetDomain(context);
                return domain != null;
            }
            catch (Exception e) {
                Logging.Logger.LogDebug("Static GetDomain call failed for domain {DomainName}: {Error}", domainName,
                    e.Message);
                domain = null;
                return false;
            }
        }

        /// <summary>
        ///     Attempts to get the Domain object representing the user's current domain. The
        ///     resolution depends on the calling thread's auth context and configured credentials,
        ///     so the result is cached per <see cref="LdapUtils"/> instance.
        /// </summary>
        public bool GetDomain(out Domain domain) {
            if (!_ldapConfig.AllowFallbackToUncontrolledLdap) {
                _log.LogDebug(
                    "GetDomain(out Domain) short-circuited: AllowFallbackToUncontrolledLdap is disabled");
                domain = null;
                return false;
            }

            if (!string.IsNullOrWhiteSpace(_ldapConfig.Server)) {
                _log.LogDebug(
                    "GetDomain() short-circuited: Specific Server is set");
                domain = null;
                return false;
            }

            // Lock-free fast path for the common case of repeated null-hint calls on a single
            // instance after the first successful resolution.
            if (_currentDomain != null) {
                domain = _currentDomain;
                return true;
            }

            // Serialize concurrent first-time resolutions on the same instance so we don't fan
            // out duplicate Domain.GetDomain RPCs.
            lock (_currentDomainLock) {
                if (_currentDomain != null) {
                    domain = _currentDomain;
                    return true;
                }

                try {
                    var context = _ldapConfig.Username != null
                        ? new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                            _ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain);

                    // Blocking External Call
                    var resolved = Domain.GetDomain(context);

                    _currentDomain = resolved;
                    domain = resolved;
                    return true;
                }
                catch (Exception e) {
                    _log.LogDebug(e, "GetDomain call failed for blank domain");
                    domain = null;
                    return false;
                }
            }
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

        public async Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain) {
            //Remove SPN prefixes from the host name so we're working with a clean name
            var strippedHost = Helpers.StripServicePrincipalName(host).ToUpper().TrimEnd('$');
            if (string.IsNullOrEmpty(strippedHost)) {
                return (false, string.Empty);
            }

            if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return (sid != null, sid);

            //Immediately start with NetWkstaGetInfo as it's our most reliable indicator if successful
            if (await GetWorkstationInfo(strippedHost) is (true, var workstationInfo)) {
                var tempName = workstationInfo.ComputerName;
                var tempDomain = workstationInfo.LanGroup;
                _log.LogTrace("Get workstation info for {HostName} succeeded. Workstation {ComputerName} found.", host, tempName);

                if (string.IsNullOrWhiteSpace(tempDomain)) {
                    tempDomain = domain;
                }

                if (!string.IsNullOrWhiteSpace(tempName)) {
                    tempName = $"{tempName}$".ToUpper();
                    if (await ResolveAccountName(tempName, tempDomain) is (true, var principal)) {
                        _hostResolutionMap.TryAdd(strippedHost, principal.ObjectIdentifier);
                        return (true, principal.ObjectIdentifier);
                    }
                }
            }

            //Try some socket magic to get the NETBIOS name
            try {
                var (requestNetBiosNameSuccess, netBiosName) = await RequestNETBIOSNameFromComputerWithTimeout(strippedHost, domain);
                if (requestNetBiosNameSuccess) {
                    if (!string.IsNullOrWhiteSpace(netBiosName)) {
                        var result = await ResolveAccountName($"{netBiosName}$", domain);
                        if (result.Success) {
                            _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                            return (true, result.Principal.ObjectIdentifier);
                        }
                    }
                }
            } catch (TimeoutException) {
                _log.LogDebug("RequestNETBIOSNameFromComputer timeout on host {Host}, domain {Domain}.", strippedHost, domain);
            }

            //Start by handling non-IP address names
            if (!IPAddress.TryParse(strippedHost, out _)) {
                //PRIMARY.TESTLAB.LOCAL
                if (strippedHost.Contains(".")) {
                    var split = strippedHost.Split('.');
                    var name = split[0];
                    var result = await ResolveAccountName($"{name}$", domain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }

                    var tempDomain = string.Join(".", split.Skip(1).ToArray());
                    result = await ResolveAccountName($"{name}$", tempDomain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
                else {
                    //Format: WIN10 (probably a netbios name)
                    var result = await ResolveAccountName($"{strippedHost}$", domain);
                    if (result.Success) {
                        _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                        return (true, result.Principal.ObjectIdentifier);
                    }
                }
            }

            try {
                // Blocking External Call
                var resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
                var split = resolvedHostname.Split('.');
                var name = split[0];
                var result = await ResolveAccountName($"{name}$", domain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }

                var tempDomain = string.Join(".", split.Skip(1).ToArray());
                result = await ResolveAccountName($"{name}$", tempDomain);
                if (result.Success) {
                    _hostResolutionMap.TryAdd(strippedHost, result.Principal.ObjectIdentifier);
                    return (true, result.Principal.ObjectIdentifier);
                }
            }
            catch {
                //pass
            }

            _hostResolutionMap.TryAdd(strippedHost, null);
            return (false, "");
        }

        /// <summary>
        ///     Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private async Task<(bool Success, NetAPIStructs.WorkstationInfo100 Info)> GetWorkstationInfo(string hostname) {
            if (!await _portScanner.CheckPort(hostname)) {
                _log.LogTrace("CheckPort returned false for {HostName}.", hostname);
                return (false, default);
            }

            // Blocking External Call
            var result = await _callNetWkstaGetInfoAdaptiveTimeout.ExecuteNetAPIWithTimeout((_) => _nativeMethods.CallNetWkstaGetInfo(hostname));

            if (result.IsSuccess)
                return (true, result.Value);
            else
                _log.LogError(result.Error);

            return (false, default);
        }

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

        private static async Task<(bool Success, string NetBiosName)> RequestNETBIOSNameFromComputerWithTimeout(string server, string domain) {
            var result = await _requestNetBiosNameAdaptiveTimeout.ExecuteWithTimeout(async (timeoutToken) => await RequestNETBIOSNameFromComputerAsync(server, domain, timeoutToken));
            if (result.IsSuccess)
                return (result.Value.Success, result.Value.NetBiosName);
            else
                throw new TimeoutException();
        }

        /// <summary>
        ///     Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static async Task<(bool Success, string NetBiosName)> RequestNETBIOSNameFromComputerAsync(string server, string domain, CancellationToken cancellationToken = default) {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress))
                    remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                    //If its not an IP, we're going to try and resolve it from DNS
                    try {
                        IPAddress address;
                        if (server.Contains("."))
                            address = (await Dns
                                .GetHostAddressesAsync(server)).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        else
                            address = (await Dns.GetHostAddressesAsync($"{server}.{domain}"))[0];

                        if (address == null) {
                            return (false, null);
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch {
                        //Failed to resolve an IP, so return null
                        return (false, null);
                    }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                cancellationToken.ThrowIfCancellationRequested();
                // Blocking External Call
                requestSocket.Bind(originEndpoint);

                try {
                    // Blocking External Call
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    cancellationToken.ThrowIfCancellationRequested();
                    // Blocking External Call
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90) {
                        var netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return (true, netbios);
                    }

                    return (false, null);
                }
                catch (SocketException) {
                    return (false, null);
                }
            }
            finally {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        /// Created for testing purposes
        /// </summary>
        /// <returns></returns>
        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor() {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(
            SecurityIdentifier sid,
            string computerDomainSid, string computerDomain) {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common)) return (false, null);
            //The "Everyone" and "Authenticated Users" principals are special and will be converted to the domain equivalent
            if (sid.Value is "S-1-1-0" or "S-1-5-11") {
                return await GetWellKnownPrincipal(sid.Value, computerDomain);
            }

            //Use the computer object id + the RID of the sid we looked up to create our new principal
            var principal = new TypedPrincipal {
                ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
                ObjectType = common.ObjectType switch {
                    Label.User => Label.LocalUser,
                    Label.Group => Label.LocalGroup,
                    _ => common.ObjectType
                }
            };

            return (true, principal);
        }

        public async Task<bool> IsDomainController(string computerObjectId, string domainName) {
            if (_domainControllers.Contains(computerObjectId)) {
                return true;
            }

            var resDomain = await GetDomainNameFromSid(domainName) is (false, var tempDomain) ? tempDomain : domainName;
            var filter = new LdapFilter().AddFilter(CommonFilters.SpecificSID(computerObjectId), true)
                .AddFilter(CommonFilters.DomainControllers, true);
            var result = await Query(new LdapQueryParameters() {
                DomainName = resDomain,
                Attributes = CommonProperties.ObjectID,
                LDAPFilter = filter.GetFilter(),
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();
            if (result.IsSuccess) {
                _domainControllers.Add(computerObjectId);
            }

            return result.IsSuccess;
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
                using (var ctx = CreatePrincipalContext(_ldapConfig, domain)) {
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

        public void AddDomainController(string domainControllerSID) {
            _domainControllers.Add(domainControllerSID);
        }

        public async IAsyncEnumerable<OutputBase> GetWellKnownPrincipalOutput() {
            foreach (var wkp in SeenWellKnownPrincipals) {
                WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
                OutputBase output = principal.ObjectType switch {
                    Label.User => new User(),
                    Label.Computer => new Computer(),
                    Label.Group => new Group(),
                    Label.GPO => new GPO(),
                    Label.Domain => new OutputTypes.Domain(),
                    Label.OU => new OU(),
                    Label.Container => new Container(),
                    Label.Configuration => new Container(),
                    _ => throw new ArgumentOutOfRangeException()
                };

                output.Properties.Add("name", $"{principal.ObjectIdentifier}@{wkp.Value.DomainName}".ToUpper());
                if (await GetDomainSidFromDomainName(wkp.Value.DomainName) is (true, var sid)) {
                    output.Properties.Add("domainsid", sid);
                }

                output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
                output.ObjectIdentifier = wkp.Key;
                yield return output;
            }

            await foreach (var entdc in GetEnterpriseDCGroups()) {
                yield return entdc;
            }
        }

        private async IAsyncEnumerable<Group> GetEnterpriseDCGroups() {
            var grouped = new ConcurrentDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var forestSidToName = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var domainSid in _domainControllers.Values().GroupBy(x =>
                         new SecurityIdentifier(x).AccountDomainSid.Value)) {
                if (await GetDomainNameFromSid(domainSid.Key) is (true, var domainName) &&
                    await GetForest(domainName) is (true, var forestName) &&
                    await GetDomainSidFromDomainName(forestName) is (true, var forestDomainSid)) {
                    forestSidToName.TryAdd(forestDomainSid, forestName);
                    if (!grouped.ContainsKey(forestDomainSid)) {
                        grouped[forestDomainSid] = new();
                    }

                    foreach (var k in domainSid) {
                        grouped[forestDomainSid].Add(k);
                    }
                }
            }

            foreach (var f in grouped) {
                if (!forestSidToName.TryGetValue(f.Key, out var forestName)) {
                    _log.LogWarning("Could not get a mapped value for well known principal {Key}", f.Key);
                    continue;
                }

                var group = new Group { ObjectIdentifier = $"{forestName}-S-1-5-9" };
                group.Properties.Add("name", $"ENTERPRISE DOMAIN CONTROLLERS@{forestName}".ToUpper());
                group.Properties.Add("domainsid", f.Key);
                group.Properties.Add("domain", forestName);
                group.Members = f.Value.Select(x => new TypedPrincipal(x, Label.Computer)).ToArray();
                yield return group;
            }
        }

        public void SetLdapConfig(LdapConfig config) {
            _ldapConfig = config;
            _log.LogInformation("New LDAP Config Set:\n {ConfigString}", config.ToString());
            // _currentDomain was resolved under the previous credentials/server, both of which
            // can have just changed. Drop it so the next GetDomain(out _) re-resolves against the
            // new auth context instead of returning a stale Domain bound to the old config.
            lock (_currentDomainLock) {
                _currentDomain?.Dispose();
                _currentDomain = null;
            }
            _connectionPool.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
        }

        public Task<(bool Success, string Message)> TestLdapConnection(string domain) {
            return _connectionPool.TestDomainConnection(domain, false);
        }

        public async Task<(bool Success, string Path)> GetNamingContextPath(string domain, NamingContext context) {
            if (await _connectionPool.GetLdapConnection(domain, false) is (true, var wrapper, _)) {
                _connectionPool.ReleaseConnection(wrapper);
                if (wrapper.GetSearchBase(context, out var searchBase)) {
                    return (true, searchBase);
                }
            }

            var property = context switch {
                NamingContext.Default => LDAPProperties.DefaultNamingContext,
                NamingContext.Configuration => LDAPProperties.ConfigurationNamingContext,
                NamingContext.Schema => LDAPProperties.SchemaNamingContext,
                _ => throw new ArgumentOutOfRangeException(nameof(context), context, null)
            };

            try {
                var entry = Helpers.CreateDirectoryEntry($"LDAP://{domain}/RootDSE", _ldapConfig);
                if (entry.TryGetProperty(property, out var searchBase)) {
                    return (true, searchBase);
                }
            }
            catch {
                //pass
            }

            // Controlled replacement for the old GetDomain(out Domain) + DomainNameToDistinguishedName
            // block. DomainInfo.DistinguishedName is the default naming context DN; Configuration and
            // Schema NCs are constructed from it the same way the old path constructed them.
            if (await GetDomainInfoAsync(domain) is (true, var domainInfo) &&
                !string.IsNullOrWhiteSpace(domainInfo?.DistinguishedName)) {
                var searchBase = context switch {
                    NamingContext.Configuration => $"CN=Configuration,{domainInfo.DistinguishedName}",
                    NamingContext.Schema => $"CN=Schema,CN=Configuration,{domainInfo.DistinguishedName}",
                    NamingContext.Default => domainInfo.DistinguishedName,
                    _ => throw new ArgumentOutOfRangeException()
                };

                return (true, searchBase);
            }

            return (false, default);
        }

        /// <summary>
        /// Counts the populated fields on a <see cref="DomainInfo"/> as a coarse measure of how
        /// much information a particular resolution tier produced. Used by <see cref="CacheDomainInfo"/>
        /// to ensure a richer record published by a later tier replaces a sparser record published
        /// by an earlier tier, instead of being dropped by <c>ConcurrentDictionary.TryAdd</c>'s
        /// first-writer-wins semantics. <see cref="DomainInfo.DomainControllers"/> is treated as
        /// "populated" only when non-empty because the constructor coalesces null to an empty array.
        /// </summary>
        internal static int CompletenessScore(DomainInfo info) {
            if (info == null) return -1;
            var score = 0;
            if (!string.IsNullOrEmpty(info.Name)) score++;
            if (!string.IsNullOrEmpty(info.DistinguishedName)) score++;
            if (!string.IsNullOrEmpty(info.ForestName)) score++;
            if (!string.IsNullOrEmpty(info.DomainSid)) score++;
            if (!string.IsNullOrEmpty(info.NetBiosName)) score++;
            if (!string.IsNullOrEmpty(info.PrimaryDomainController)) score++;
            if (info.DomainControllers != null && info.DomainControllers.Count > 0) score++;
            return score;
        }

        /// <summary>
        /// Inserts <paramref name="candidate"/> at <paramref name="key"/> in
        /// <see cref="_domainInfoCache"/>, replacing any existing entry only when the candidate has
        /// strictly more populated fields (per <see cref="CompletenessScore"/>). Equal scores
        /// preserve the existing entry to keep cache writes idempotent under concurrent resolution.
        /// </summary>
        /// <remarks>
        /// The four resolution tiers behind <see cref="GetDomainInfoAsync(string)"/> and
        /// <see cref="GetDomainInfoStaticAsync"/> populate different attribute subsets - notably
        /// only the pool-driven <see cref="ResolveDomainInfoControlledAsyncCore"/> path queries
        /// <c>CN=Partitions</c> for <see cref="DomainInfo.NetBiosName"/>. Because the static helper
        /// is invoked re-entrantly from <see cref="ConnectionPoolManager.GetDomainSidFromDomainName"/>
        /// during pool acquisition, the sparser one-shot direct-LDAP record reaches the cache first;
        /// without the score guard the subsequent pool-derived record would be silently discarded by
        /// <c>TryAdd</c> and every later cache hit would observe the partial record.
        /// <para>
        /// The cross-domain guard (<see cref="KeyMatchesCandidate"/>) prevents cache poisoning when
        /// a misconfigured <see cref="LdapConfig.Server"/> pin or a cross-forest leak causes a tier
        /// to return a <see cref="DomainInfo"/> describing a different domain than the one the
        /// caller asked about. On every successful write the entry is also mirrored under
        /// <see cref="DomainInfo.Name"/> when that differs from <paramref name="key"/>, so
        /// subsequent lookups by a different alias form (NetBIOS short name vs. DNS FQDN) hit the
        /// same richest-available record.
        /// </para>
        /// </remarks>
        internal static void CacheDomainInfo(string key, DomainInfo candidate) {
            if (key == null || candidate == null) return;
            if (!KeyMatchesCandidate(key, candidate)) return;

            DomainInfo PickRicher(string _, DomainInfo existing)
                => CompletenessScore(candidate) > CompletenessScore(existing) ? candidate : existing;

            _domainInfoCache.AddOrUpdate(key, candidate, PickRicher);

            if (!string.IsNullOrWhiteSpace(candidate.Name)
                && !string.Equals(key, candidate.Name, StringComparison.OrdinalIgnoreCase)) {
                _domainInfoCache.AddOrUpdate(candidate.Name, candidate, PickRicher);
            }
        }

        /// <summary>
        /// Returns <c>true</c> when <paramref name="key"/> identifies the same domain that
        /// <paramref name="candidate"/> describes, comparing case-insensitively against
        /// <see cref="DomainInfo.Name"/> and <see cref="DomainInfo.NetBiosName"/>. Candidates
        /// with no <see cref="DomainInfo.Name"/> are rejected: the resolution tiers contract is
        /// to populate Name on every successful return, so a Name-less candidate is by definition
        /// unverifiable and caching it under the caller's key would silently associate a broken
        /// record with that domain.
        /// </summary>
        private static bool KeyMatchesCandidate(string key, DomainInfo candidate) {
            if (string.IsNullOrEmpty(candidate.Name)) return false;
            if (string.Equals(key, candidate.Name, StringComparison.OrdinalIgnoreCase)) return true;
            if (!string.IsNullOrEmpty(candidate.NetBiosName)
                && string.Equals(key, candidate.NetBiosName, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>
        /// Picks the richer of <paramref name="seed"/> and <paramref name="enriched"/>, guarding
        /// against cross-domain leakage when an enrichment retry binds to a DC discovered by an
        /// earlier tier. Returns <paramref name="seed"/> unchanged when <paramref name="enriched"/>
        /// is null, when the two records describe different canonical domain names, or when the
        /// enriched record does not have strictly more populated fields per
        /// <see cref="CompletenessScore"/>.
        /// </summary>
        /// <remarks>
        /// The name-equality guard is deliberately strict: an enrichment retry that binds to the
        /// PDC discovered by ADSI (or any other tier) and reads a different <c>defaultNamingContext</c>
        /// than the seed indicates the retry landed on a DC that is not actually in the requested
        /// domain (cross-forest leak, decommissioned host, mismatched <c>config.Server</c>). In that
        /// case the seed is preferred even though the retry produced a higher score, because caching
        /// the retry's record under the seed's cache key would silently associate the wrong SID and
        /// NetBIOS name with that domain. A missing Name on either side is treated as a guard
        /// failure (rather than letting <c>string.Equals(null, null)</c> wave through the merge),
        /// since a Name-less record cannot be safely compared to anything.
        /// </remarks>
        internal static DomainInfo SelectRicherDomainInfo(DomainInfo seed, DomainInfo enriched) {
            if (seed == null) return enriched;
            if (enriched == null) return seed;
            if (string.IsNullOrEmpty(seed.Name) || string.IsNullOrEmpty(enriched.Name)) return seed;
            if (!string.Equals(seed.Name, enriched.Name, StringComparison.OrdinalIgnoreCase)) {
                return seed;
            }
            return CompletenessScore(enriched) > CompletenessScore(seed) ? enriched : seed;
        }

        /// <summary>
        /// Resolves a <see cref="DomainInfo"/> for the specified domain, preferring a controlled
        /// LDAP path that honors the configured <see cref="LdapConfig"/> (server, port, SSL,
        /// AuthType, signing, cert verification, credentials).
        /// </summary>
        /// <remarks>
        /// Walks <see cref="ResolveDomainInfoAsync"/> with this instance's connection pool and
        /// config, after substituting a current-user domain hint via
        /// <see cref="ResolveEffectiveDomainHint"/> when <paramref name="domainName"/> is empty.
        /// Successful results are cached in the static <see cref="_domainInfoCache"/> for the
        /// lifetime of the process (until <see cref="ResetUtils"/> is invoked).
        /// </remarks>
        public Task<(bool Success, DomainInfo DomainInfo)> GetDomainInfoAsync(string domainName) {
            var hint = ResolveEffectiveDomainHint(domainName);
            return ResolveDomainInfoAsync(hint, _connectionPool, _ldapConfig, _log);
        }

        /// <summary>
        /// Convenience overload that resolves a <see cref="DomainInfo"/> for the user's current
        /// domain. Equivalent to calling <see cref="GetDomainInfoAsync(string)"/> with <c>null</c>.
        /// </summary>
        public Task<(bool Success, DomainInfo DomainInfo)> GetDomainInfoAsync() {
            return GetDomainInfoAsync(null);
        }

        /// <summary>
        /// Static, uncoalesced counterpart to <see cref="GetDomainInfoAsync(string)"/> intended for
        /// internal consumers that cannot hold an <see cref="ILdapUtils"/> instance (notably
        /// <see cref="ConnectionPoolManager"/> and <see cref="LdapConnectionPool"/>, which are
        /// themselves pieces of the connection infrastructure and can't reenter it transparently).
        /// </summary>
        /// <param name="domainName">The target domain. Must be non-empty; this entry point does not resolve a default.</param>
        /// <param name="config">Config used to honor the <see cref="LdapConfig.AllowFallbackToUncontrolledLdap"/> gate and to build fallback credentials.</param>
        /// <param name="log">Logger used for debug-level diagnostics on failure paths.</param>
        /// <remarks>
        /// Results are stored in the same static <see cref="_domainInfoCache"/> used by the
        /// instance overload, so a successful lookup here also benefits later
        /// <see cref="GetDomainInfoAsync(string)"/> calls on the same process. The pool tier is
        /// skipped here because no <see cref="ConnectionPoolManager"/> is available; the remaining
        /// three tiers (one-shot direct LDAP, ADSI, uncontrolled fallback) still run.
        /// <para>
        /// Deliberately bypasses <see cref="_inFlightDomainResolutions"/>. This entry point exists
        /// for re-entrant pool callers (the pool tier resolves a domain SID by calling here while
        /// itself executing inside a coalesced instance walk for the same domain). Coalescing the
        /// re-entrant call against the outer pool-tier Lazy would self-deadlock, since that Lazy
        /// has not yet published its Task. Concurrent non-recursive callers will each run the
        /// non-pool tier walk independently; the cache write performed by the first to finish
        /// short-circuits subsequent callers via the cache check above.
        /// </para>
        /// </remarks>
        internal static Task<(bool Success, DomainInfo DomainInfo)> GetDomainInfoStaticAsync(
            string domainName, LdapConfig config, ILogger log = null) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                return Task.FromResult<(bool, DomainInfo)>((false, null));
            }

            if (_domainInfoCache.TryGetValue(domainName, out var cached)) {
                return Task.FromResult((true, cached));
            }

            return ResolveDomainInfoCoreAsync(domainName, pool: null, config, log);
        }

        /// <summary>
        /// Coalesced resolution entry point used by the instance <see cref="GetDomainInfoAsync(string)"/>
        /// path. Drives the full four-tier walk (pool LDAP, one-shot direct LDAP, ADSI, uncontrolled
        /// fallback) and serializes concurrent first-time callers for the same domain through
        /// <see cref="_inFlightDomainResolutions"/> so N callers observe one shared tier walk.
        /// </summary>
        /// <remarks>
        /// The first caller's <paramref name="pool"/>, <paramref name="config"/>, and
        /// <paramref name="log"/> are captured by the lazy; subsequent awaiters inherit those. In
        /// practice all <see cref="LdapUtils"/> instances in a process share the same effective
        /// config, so this matches the ambient assumption already made by the static
        /// <see cref="_domainInfoCache"/>.
        /// <para>
        /// Any cached record satisfies this lookup regardless of which tier produced it. Upgrade
        /// from a sparser seed to a richer record happens at write time via
        /// <see cref="CompletenessScore"/> in <see cref="CacheDomainInfo"/>; the read path does not
        /// re-resolve a cached domain just because some attribute (e.g. <see cref="DomainInfo.NetBiosName"/>)
        /// is absent, since attributes that are unreachable for the configured credentials would
        /// otherwise trigger an unbounded re-resolution loop on every call.
        /// </para>
        /// </remarks>
        private static async Task<(bool Success, DomainInfo DomainInfo)> ResolveDomainInfoAsync(
            string domainName, ConnectionPoolManager pool, LdapConfig config, ILogger log) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                return (false, null);
            }

            if (_domainInfoCache.TryGetValue(domainName, out var cached)) {
                return (true, cached);
            }

            var lazy = _inFlightDomainResolutions.GetOrAdd(domainName,
                key => new Lazy<Task<(bool Success, DomainInfo DomainInfo)>>(
                    () => ResolveDomainInfoCoreAsync(key, pool, config, log),
                    LazyThreadSafetyMode.ExecutionAndPublication));

            try {
                return await lazy.Value.ConfigureAwait(false);
            }
            finally {
                _inFlightDomainResolutions.TryRemove(domainName, out _);
            }
        }

        /// <summary>
        /// Drives the actual four-tier walk for <see cref="ResolveDomainInfoAsync"/>. Wrapped by a
        /// per-domain <see cref="Lazy{T}"/> so concurrent first-time callers share the result.
        /// </summary>
        /// <remarks>
        /// Tier ordering rationale: the pool tier honors every <see cref="LdapConfig"/> flag and
        /// is preferred when available. The one-shot direct-LDAP tier is tried before ADSI because
        /// it is the only tier outside the pool that can express fine-grained
        /// <see cref="LdapConfig.AuthType"/> and <see cref="LdapConfig.DisableCertVerification"/> -
        /// running ADSI first would silently ignore those flags whenever its serverless bind
        /// happened to succeed. The ADSI and uncontrolled-fallback tiers are followed by a
        /// direct-LDAP enrichment pass against the discovered PDC so the cached record reaches the
        /// same shape as the pool and one-shot tiers.
        /// </remarks>
        private static async Task<(bool Success, DomainInfo DomainInfo)> ResolveDomainInfoCoreAsync(
            string domainName, ConnectionPoolManager pool, LdapConfig config, ILogger log) {
            // Re-check inside the lazy: another caller may have published a record between our
            // outer cache miss and this lazy's first execution.
            if (_domainInfoCache.TryGetValue(domainName, out var cached)) {
                return (true, cached);
            }

            if (pool != null) {
                var (poolOk, poolInfo) = await ResolveDomainInfoControlledAsyncCore(domainName, pool, log);
                if (poolOk) {
                    CacheDomainInfo(domainName, poolInfo);
                    return (true, poolInfo);
                }
            }

            var (directOk, directInfo) = await TryResolveDomainInfoViaDirectLdapAsync(domainName, config, log);
            if (directOk) {
                CacheDomainInfo(domainName, directInfo);
                return (true, directInfo);
            }

            var (adsiOk, adsiInfo) = await TryResolveDomainInfoViaDirectoryEntryAsync(domainName, config, log);
            if (adsiOk) {
                adsiInfo = await TryEnrichDomainInfoViaDirectLdapAsync(domainName, adsiInfo, config, log);
                CacheDomainInfo(domainName, adsiInfo);
                return (true, adsiInfo);
            }

            if (TryGetDomainInfoViaUncontrolledFallback(domainName, config, log, out var fallbackInfo)) {
                fallbackInfo = await TryEnrichDomainInfoViaDirectLdapAsync(
                    domainName, fallbackInfo, config, log);
                CacheDomainInfo(domainName, fallbackInfo);
                return (true, fallbackInfo);
            }

            return (false, null);
        }

        /// <summary>
        /// Resolves the domain name to use when the caller did not supply one. Walks a five-step
        /// preference order designed to maximize resolution success without paying an RPC on the
        /// common path.
        /// </summary>
        /// <remarks>
        /// Order of preference:
        /// <list type="number">
        ///   <item><b>Explicit <paramref name="domainName"/></b> — caller-supplied; always wins.</item>
        ///   <item><b><see cref="LdapConfig.CurrentUserDomain"/></b> — deterministic escape hatch for any
        ///     scenario where the OS-provided hint is wrong. Preferred over the uncontrolled tier below
        ///     because it's free and doesn't require opting into uncontrolled calls.</item>
        ///   <item><b><see cref="Environment.UserDomainName"/></b>, <i>only when it differs from
        ///     <see cref="Environment.MachineName"/></i>. The env var returning the machine name is a
        ///     reliable signal that the primary token carries no domain identity (netonly, workgroup,
        ///     LocalSystem with no stored creds). In every other case - normal interactive logons,
        ///     regular <c>runas</c>, service accounts in a joined machine's domain - the env var is
        ///     correct and this branch short-circuits the rest of the resolver at zero cost.</item>
        ///   <item><b>Uncontrolled DC-locator via <c>Domain.GetDomain</c></b> (see
        ///     <see cref="TryResolveHintViaUncontrolledGetDomain"/>). Only fires when
        ///     <see cref="LdapConfig.AllowFallbackToUncontrolledLdap"/> is on. Issues
        ///     <c>Domain.GetDomain(new DirectoryContext(Domain))</c> with no explicit credentials or
        ///     target, letting the SDS/DsGetDcName stack resolve the current user's domain from the
        ///     thread's outbound authentication context. In <c>runas /netonly</c> that context is the
        ///     alt credential (not the local primary token that step 3 failed on), so this recovers
        ///     the real target domain. The RPC is issued on every call that reaches this tier; the
        ///     resolved hint becomes the <see cref="_domainInfoCache"/> key on success so subsequent
        ///     resolutions for the same domain short-circuit at the controlled-LDAP tier.</item>
        ///   <item><b>Last-resort <see cref="Environment.UserDomainName"/></b> even when it equals the
        ///     machine name. Downstream tiers will almost certainly fail to bind against this, but
        ///     returning the env var here keeps behavior identical to the pre-change code for users who
        ///     haven't opted into the uncontrolled fallback.</item>
        /// </list>
        /// </remarks>
        internal string ResolveEffectiveDomainHint(string domainName) {
            // 1. Explicit argument wins unconditionally.
            if (!string.IsNullOrWhiteSpace(domainName))
                return domainName;

            // 2. Config-provided override. Cheap, deterministic, no network I/O.
            if (!string.IsNullOrWhiteSpace(_ldapConfig?.CurrentUserDomain))
                return _ldapConfig.CurrentUserDomain;

            // 3. Env var, but only when it actually carries a domain identity. UserDomainName ==
            //    MachineName is the canonical signal for "no domain on the primary token" and covers
            //    netonly, workgroup, and LocalSystem cases without false positives on domain-joined
            //    setups (where the two always differ).
            var envDomain = Environment.UserDomainName;
            if (!string.IsNullOrWhiteSpace(envDomain) &&
                !string.Equals(envDomain, Environment.MachineName, StringComparison.OrdinalIgnoreCase)) {
                return envDomain;
            }

            // 4. Opt-in uncontrolled DC-locator. Only pays the RPC when step 3 determined the env var
            //    is unusable AND the caller has explicitly allowed uncontrolled calls. No credentials
            //    are passed - the SDS stack uses the thread's outbound auth context, which in netonly
            //    is the alt credential rather than the local primary token.
            if (TryResolveHintViaUncontrolledGetDomain(_ldapConfig, _log, out var credDomain)) {
                return credDomain;
            }

            // 5. Preserve pre-change behavior: return the env var even if it's the machine name.
            //    Lets downstream tiers decide how to fail.
            return envDomain;
        }

        /// <summary>
        /// Uncontrolled hint resolver that invokes <c>Domain.GetDomain(new DirectoryContext(Domain))</c>
        /// with no explicit credentials or target name, letting the SDS/DsGetDcName stack resolve the
        /// domain from the current thread's outbound authentication context. Gated behind
        /// <see cref="LdapConfig.AllowFallbackToUncontrolledLdap"/> because it makes an unmanaged
        /// DC-locator RPC that bypasses every other <see cref="LdapConfig"/> flag.
        /// </summary>
        /// <remarks>
        /// Complements step 3 in <see cref="ResolveEffectiveDomainHint"/>: that step consults
        /// <see cref="Environment.UserDomainName"/>, which reads the process's primary token. In
        /// <c>runas /netonly</c> the primary token is the local machine, so that value is useless;
        /// however the LSA still attaches the alt credential to the thread for outbound network auth,
        /// and <c>DsGetDcName</c> uses that context to locate a DC for the alt credential's actual
        /// domain. Passing no username/password here is deliberate -
        /// <see cref="LdapConfig.Username"/> is not guaranteed to be a UPN or downlevel name, so
        /// supplying it to <see cref="DirectoryContext"/> could misdirect the locator; the
        /// credential-less form instead lets Windows use whatever authentication context is already
        /// bound to the thread.
        /// </remarks>
        private static bool TryResolveHintViaUncontrolledGetDomain(
            LdapConfig config, ILogger log, out string domainName) {
            domainName = null;

            // Hard gate: uncontrolled calls require explicit opt-in.
            if (config is not { AllowFallbackToUncontrolledLdap: true }) return false;

            if (!string.IsNullOrWhiteSpace(config.Server)) {
                log?.LogDebug(
                    "TryResolveHintViaUncontrolledGetDomain short-circuited: Server={Server} is set",
                    config.Server);
                return false;
            }

            try {
                // No name, no credentials: SDS resolves via the thread's outbound auth context,
                // which is what surfaces the alt-creds domain under runas /netonly.
                var ctx = new DirectoryContext(DirectoryContextType.Domain);
                var domain = Domain.GetDomain(ctx);
                var name = domain?.Name;
                if (!string.IsNullOrEmpty(name)) {
                    domainName = name;
                    return true;
                }
            }
            catch (Exception e) {
                log?.LogDebug(e,
                    "TryResolveHintViaUncontrolledGetDomain: Domain.GetDomain failed");
            }

            return false;
        }

        /// <summary>
        /// Core controlled-LDAP resolver. Builds a <see cref="DomainInfo"/> using only queries
        /// that flow through the supplied <see cref="ConnectionPoolManager"/>, so every call
        /// honors the <see cref="LdapConfig"/> attached to that pool.
        /// </summary>
        /// <remarks>
        /// Work performed, in order:
        /// <list type="number">
        ///   <item>Acquire a pooled connection to <paramref name="domainName"/>. The wrapper's cached rootDSE
        ///   supplies <c>defaultNamingContext</c> and <c>configurationNamingContext</c> without an extra round-trip.</item>
        ///   <item>Base search on the domain NC (<c>objectClass=*</c>) for <c>objectSid</c> (domain SID),
        ///   <c>rootDomainNamingContext</c> (forest root, used to compute <see cref="DomainInfo.ForestName"/>)
        ///   and <c>fSMORoleOwner</c> (PDC FSMO owner; stored as a DN to the NTDS Settings object).</item>
        ///   <item>If the PDC owner DN is resolved, a follow-up Base search on the owner's parent
        ///   server object retrieves <c>dNSHostName</c> to populate <see cref="DomainInfo.PrimaryDomainController"/>.</item>
        ///   <item>OneLevel search under <c>CN=Partitions,&lt;configNc&gt;</c> filtered by <c>nCName</c>
        ///   retrieves the legacy NetBIOS domain name from the matching crossRef object.</item>
        ///   <item>Subtree search on the domain NC for domain controllers
        ///   (<c>userAccountControl:1.2.840.113556.1.4.803:=8192</c>) collects DNS hostnames into
        ///   <see cref="DomainInfo.DomainControllers"/>; if the PDC lookup failed, the first DC is used as a fallback.</item>
        /// </list>
        /// All follow-up queries after the initial NC read are wrapped in try/catch and only
        /// populate optional fields - a failure here still returns a partially-filled
        /// <see cref="DomainInfo"/> . A failure
        /// to acquire the connection or to read the default NC is fatal and returns <c>(false, null)</c>.
        /// </remarks>
        private static async Task<(bool Success, DomainInfo DomainInfo)> ResolveDomainInfoControlledAsyncCore(
            string domainName, ConnectionPoolManager pool, ILogger log) {
            if (string.IsNullOrWhiteSpace(domainName) || pool == null) {
                return (false, null);
            }

            // Acquire a pooled connection to harvest rootDSE-derived naming contexts.
            var (ok, wrapper, _) = await pool.GetLdapConnection(domainName, false);
            if (!ok || wrapper == null) {
                return (false, null);
            }

            // GetSearchBase reads from the wrapper's cached rootDSE entry populated when the
            // connection was established - no additional LDAP traffic is issued here. We release
            // the connection immediately so subsequent Query(...) calls can reuse it from the pool.
            string defaultNc;
            string configNc;
            try {
                wrapper.GetSearchBase(NamingContext.Default, out defaultNc);
                wrapper.GetSearchBase(NamingContext.Configuration, out configNc);
            }
            finally {
                pool.ReleaseConnection(wrapper);
            }

            if (string.IsNullOrWhiteSpace(defaultNc)) {
                return (false, null);
            }

            // Canonical name is always derivable from the default NC (e.g. DC=contoso,DC=local -> CONTOSO.LOCAL).
            // DistinguishedNameToDomain returns null for DNs without DC= components; a tier success contract
            // requires a populated Name so reject the result rather than emitting a Name-less DomainInfo.
            var derivedName = Helpers.DistinguishedNameToDomain(defaultNc);
            if (string.IsNullOrEmpty(derivedName)) return (false, null);
            var name = derivedName.ToUpper();
            string domainSid = null;
            string forestName = null;
            string primaryDomainController = null;
            string netBiosName = null;
            IReadOnlyList<string> domainControllers = null;

            // Base search on the domain NC harvests the domain SID, forest root NC, and PDC FSMO owner DN
            // in a single round-trip.
            try {
                var baseRes = await pool.Query(new LdapQueryParameters {
                    DomainName = domainName,
                    SearchBase = defaultNc,
                    SearchScope = SearchScope.Base,
                    LDAPFilter = "(objectClass=*)",
                    Attributes = new[] {
                        LDAPProperties.ObjectSID,
                        LDAPProperties.RootDomainNamingContext,
                        LDAPProperties.FSMORoleOwner,
                    },
                }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

                if (baseRes.IsSuccess) {
                    // objectSid on the domain NC itself is the domain SID (S-1-5-21-a-b-c).
                    if (baseRes.Value.TryGetSecurityIdentifier(out var sid) && !string.IsNullOrEmpty(sid)) {
                        domainSid = sid.ToUpper();
                    }

                    // rootDomainNamingContext points at the forest root domain's NC even when queried
                    // against a child domain, giving us the forest name without a separate GC lookup.
                    if (baseRes.Value.TryGetProperty(LDAPProperties.RootDomainNamingContext, out var rootNc) &&
                        !string.IsNullOrEmpty(rootNc)) {
                        forestName = Helpers.DistinguishedNameToDomain(rootNc).ToUpper();
                    }

                    // fSMORoleOwner on the domain NC is a DN to the NTDS Settings object of the PDC,
                    // e.g. "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,...".
                    // Strip the NTDS Settings RDN to get the Server object DN, then read its dNSHostName.
                    if (baseRes.Value.TryGetProperty(LDAPProperties.FSMORoleOwner, out var fsmoOwner) &&
                        TryStripNtdsSettingsPrefix(fsmoOwner, out var serverDn)) {
                        var pdcRes = await pool.Query(new LdapQueryParameters {
                            DomainName = domainName,
                            SearchBase = serverDn,
                            SearchScope = SearchScope.Base,
                            LDAPFilter = "(objectClass=*)",
                            Attributes = new[] { LDAPProperties.DNSHostName },
                        }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

                        if (pdcRes.IsSuccess &&
                            pdcRes.Value.TryGetProperty(LDAPProperties.DNSHostName, out var pdcName)) {
                            primaryDomainController = pdcName;
                        }
                    }
                }
            }
            catch (Exception ex) {
                log?.LogDebug(ex, "ResolveDomainInfoControlled: base query failed for {Domain}", domainName);
            }

            // NetBIOS name lives on the crossRef entry whose nCName matches the domain NC. Cross-references
            // live under CN=Partitions in the configuration NC, so this query only runs if we read the
            // configuration NC above.
            if (!string.IsNullOrWhiteSpace(configNc)) {
                try {
                    var nbRes = await pool.Query(new LdapQueryParameters {
                        DomainName = domainName,
                        SearchBase = $"CN=Partitions,{configNc}",
                        SearchScope = SearchScope.OneLevel,
                        LDAPFilter = $"(&(objectClass=crossRef)({LDAPProperties.NCName}={defaultNc}))",
                        Attributes = new[] { LDAPProperties.NetbiosName },
                    }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

                    if (nbRes.IsSuccess && nbRes.Value.TryGetProperty(LDAPProperties.NetbiosName, out var nb)) {
                        netBiosName = nb;
                    }
                }
                catch (Exception ex) {
                    log?.LogDebug(ex, "ResolveDomainInfoControlled: netbios lookup failed for {Domain}", domainName);
                }
            }

            // DC enumeration uses the canonical "DC object = computer with SERVER_TRUST_ACCOUNT in UAC"
            // bit test (0x2000). This is the same filter used elsewhere in the project via CommonFilters.
            try {
                var dcs = new List<string>();
                var dcEnum = pool.Query(new LdapQueryParameters {
                    DomainName = domainName,
                    SearchBase = defaultNc,
                    LDAPFilter = CommonFilters.DomainControllers,
                    Attributes = new[] { LDAPProperties.DNSHostName },
                });
                await foreach (var dcRes in dcEnum) {
                    if (dcRes.IsSuccess &&
                        dcRes.Value.TryGetProperty(LDAPProperties.DNSHostName, out var dcName) &&
                        !string.IsNullOrEmpty(dcName)) {
                        dcs.Add(dcName);
                    }
                }

                domainControllers = dcs;
                // Last-resort PDC: if the FSMO resolution above failed, any DC is a reasonable
                // fallback target for callers that just want a working DC name.
                if (string.IsNullOrEmpty(primaryDomainController) && dcs.Count > 0) {
                    primaryDomainController = dcs[0];
                }
            }
            catch (Exception ex) {
                log?.LogDebug(ex, "ResolveDomainInfoControlled: DC enumeration failed for {Domain}", domainName);
            }

            return (true, new DomainInfo(
                name: name,
                distinguishedName: defaultNc,
                forestName: forestName,
                domainSid: domainSid,
                netBiosName: netBiosName,
                primaryDomainController: primaryDomainController,
                domainControllers: domainControllers));
        }

        /// <summary>
        /// Strips the leading <c>CN=NTDS Settings,</c> RDN from a FSMO role owner DN, yielding the
        /// DN of the parent Server object. AD stores FSMO ownership as a DN pointing at the NTDS
        /// Settings object nested under the server, but the <c>dNSHostName</c> attribute lives on
        /// the server one level up.
        /// </summary>
        /// <returns>True if the prefix was found and a non-empty parent DN was produced.</returns>
        internal static bool TryStripNtdsSettingsPrefix(string fsmoRoleOwnerDn, out string serverDn) {
            serverDn = null;
            if (string.IsNullOrEmpty(fsmoRoleOwnerDn)) return false;
            const string prefix = "CN=NTDS Settings,";
            if (!fsmoRoleOwnerDn.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            serverDn = fsmoRoleOwnerDn.Substring(prefix.Length);
            return !string.IsNullOrEmpty(serverDn);
        }

        /// <summary>
        /// Uncontrolled fallback that populates a <see cref="DomainInfo"/> by calling
        /// <c>System.DirectoryServices.ActiveDirectory.Domain.GetDomain</c>.
        /// </summary>
        /// <remarks>
        /// This path is intentionally <b>opt-in</b>: it returns <c>false</c> immediately unless
        /// <see cref="LdapConfig.AllowFallbackToUncontrolledLdap"/> is set. When enabled, it mirrors
        /// the exact <see cref="DirectoryContext"/> construction used by the legacy
        /// <c>LdapUtils.GetDomain</c> overloads so behavior is bit-identical to the pre-change code.
        /// <para>
        /// The call into <c>Domain.GetDomain</c> does not honor any <see cref="LdapConfig"/> flag
        /// beyond the username/password branches - server, port, SSL, signing, and cert-verification
        /// settings are all bypassed because that API performs its own DC discovery via the native
        /// DS RPC stack.
        /// </para>
        /// <para>
        /// Every optional property access (<c>Forest</c>, <c>PdcRoleOwner</c>, <c>DomainControllers</c>,
        /// <c>GetDirectoryEntry</c>) is wrapped in its own try/catch because each of these can
        /// blocking-dial the network or attempt delegated auth and may fail independently even
        /// when the top-level <c>Domain</c> was obtained successfully.
        /// </para>
        /// </remarks>
        private static bool TryGetDomainInfoViaUncontrolledFallback(string domainName, LdapConfig config,
            ILogger log, out DomainInfo info) {
            info = null;
            // Hard gate - when the flag is off this method is a no-op regardless of what the
            // surrounding LDAP config looks like.
            if (config is not { AllowFallbackToUncontrolledLdap: true }) {
                return false;
            }
            
            if (!string.IsNullOrWhiteSpace(config.Server)) {
                log.LogDebug(
                    "TryGetDomainInfoViaUncontrolledFallback(\"{Name}\", out DomainInfo info) short-circuited: Specific Server is set",
                    domainName);
                return false;
            }
            

            try {
                // Matches the DirectoryContext construction in the legacy GetDomain overloads so
                // enabling this fallback yields identical results to the pre-change code path.
                DirectoryContext context;
                if (config.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, config.Username,
                            config.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, config.Username, config.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                // Blocking External Call
                using var domain = Domain.GetDomain(context);
                if (domain == null || string.IsNullOrEmpty(domain.Name)) {
                    return false;
                }

                var name = domain.Name.ToUpper();
                var distinguishedName = Helpers.DomainNameToDistinguishedName(domain.Name);
                string forestName = null;
                string primaryDomainController = null;
                string domainSid = null;
                IReadOnlyList<string> domainControllers = null;

                // Forest lookup triggers a separate bind under the hood; swallow any failure and
                // leave ForestName null rather than losing the rest of the DomainInfo.
                try {
                    forestName = domain.Forest?.Name?.ToUpper();
                }
                catch {
                    //pass
                }

                // PdcRoleOwner.Name is the DNS hostname of the PDC. Separately guarded because
                // it performs its own RPC lookup.
                try {
                    primaryDomainController = domain.PdcRoleOwner?.Name;
                }
                catch {
                    //pass
                }

                // DomainControllers enumeration discovers DCs via DsGetDcName; each property
                // access on a returned controller can also fault independently.
                try {
                    var dcs = new List<string>();
                    foreach (DomainController dc in domain.DomainControllers) {
                        try {
                            if (!string.IsNullOrEmpty(dc?.Name)) dcs.Add(dc.Name);
                        }
                        catch {
                            //pass
                        }
                    }

                    domainControllers = dcs;
                }
                catch {
                    //pass
                }

                // GetDirectoryEntry binds to the domain NC via SDS and reads objectSid. Cheapest
                // way to get the domain SID from an already-resolved Domain object without another
                // DirectoryContext round-trip. The raw DirectoryEntry inherits only the
                // DirectoryContext credentials, so apply the LdapConfig transport/auth flags
                // (matching Helpers.CreateDirectoryEntry) before the first property access forces
                // the bind.
                try {
                    using var rawEntry = domain.GetDirectoryEntry();
                    var authType = AuthenticationTypes.Secure;
                    if (config.ForceSSL) {
                        authType |= AuthenticationTypes.SecureSocketsLayer;
                    }
                    if (!config.DisableSigning && !config.ForceSSL) {
                        authType |= AuthenticationTypes.Signing | AuthenticationTypes.Sealing;
                    }
                    rawEntry.AuthenticationType = authType;
                    if (config.Username != null) {
                        rawEntry.Username = config.Username;
                        rawEntry.Password = config.Password;
                    }

                    var entry = rawEntry.ToDirectoryObject();
                    if (entry.TryGetSecurityIdentifier(out var sid) && !string.IsNullOrEmpty(sid)) {
                        domainSid = sid.ToUpper();
                    }
                }
                catch {
                    //pass
                }

                info = new DomainInfo(
                    name: name,
                    distinguishedName: distinguishedName,
                    forestName: forestName,
                    domainSid: domainSid,
                    primaryDomainController: primaryDomainController,
                    domainControllers: domainControllers);
                return true;
            }
            catch (Exception e) {
                log?.LogDebug(e, "TryGetDomainInfoViaUncontrolledFallback failed for domain {Name}", domainName);
                return false;
            }
        }

        /// <summary>
        /// Controlled resolver that uses ADSI (<see cref="System.DirectoryServices.DirectoryEntry"/>)
        /// via <see cref="Helpers.CreateDirectoryEntry"/>. Sits after the one-shot
        /// <see cref="LdapConnection"/> path in <see cref="GetDomainInfoAsync(string)"/> and
        /// <see cref="GetDomainInfoStaticAsync"/>, acting as a DC-locator-aware fallback for the
        /// cases the raw-LDAP tier cannot resolve on its own.
        /// </summary>
        /// <remarks>
        /// ADSI's serverless binding transparently invokes <c>DsGetDcName</c> under the hood, so
        /// NetBIOS short names and environments where <paramref name="domainName"/> has no direct
        /// DNS A record still bind here after the preceding one-shot <see cref="LdapConnection"/>
        /// tier could not locate a DC. ADSI honors <see cref="LdapConfig.Username"/>,
        /// <see cref="LdapConfig.Password"/>, <see cref="LdapConfig.Server"/>,
        /// <see cref="LdapConfig.ForceSSL"/>, and <see cref="LdapConfig.DisableSigning"/>. It
        /// cannot honor <see cref="LdapConfig.DisableCertVerification"/> (no ADSI API) or
        /// fine-grained <see cref="LdapConfig.AuthType"/> selection (always Negotiate via
        /// <c>AuthenticationTypes.Secure</c>), which is precisely why this tier is ordered *after*
        /// the one-shot path: callers that configured those flags will have them respected by the
        /// raw-LDAP tier and only reach ADSI if that tier failed outright.
        /// <para>
        /// Populates <see cref="DomainInfo.Name"/>, <see cref="DomainInfo.DistinguishedName"/>,
        /// <see cref="DomainInfo.DomainSid"/>, <see cref="DomainInfo.ForestName"/>, and
        /// <see cref="DomainInfo.PrimaryDomainController"/>. Does not populate
        /// <see cref="DomainInfo.DomainControllers"/> or <see cref="DomainInfo.NetBiosName"/>;
        /// those are only populated by the pool-based tier, which enumerates via subtree search.
        /// </para>
        /// <para>
        /// ADSI property access is synchronous and blocking; the body is offloaded to a
        /// <see cref="Task.Run(System.Action)"/> thread-pool task so callers remain non-blocking.
        /// </para>
        /// </remarks>
        private static async Task<(bool Success, DomainInfo DomainInfo)> TryResolveDomainInfoViaDirectoryEntryAsync(
            string domainName, LdapConfig config, ILogger log) {
            if (string.IsNullOrWhiteSpace(domainName) || config == null) {
                return (false, null);
            }

            return await Task.Run<(bool Success, DomainInfo DomainInfo)>(() => {
                string name;
                string distinguishedName;
                string domainSid = null;
                string forestName = null;
                string primaryDomainController = null;
                IDirectoryObject root;
                try {
                    root = Helpers.CreateDirectoryEntry($"LDAP://{domainName}", config);

                    // Force the bind by reading the DN. When the bind fails (unreachable DC, auth
                    // failure, etc.) TryGetDistinguishedName swallows the underlying COMException
                    // and returns false.
                    if (!root.TryGetDistinguishedName(out var defaultNc) ||
                        string.IsNullOrWhiteSpace(defaultNc)) {
                        return (false, null);
                    }

                    var derivedName = Helpers.DistinguishedNameToDomain(defaultNc);
                    if (string.IsNullOrEmpty(derivedName)) return (false, null);
                    name = derivedName.ToUpper();
                    distinguishedName = defaultNc;

                    if (root.TryGetSecurityIdentifier(out var sid) && !string.IsNullOrEmpty(sid)) {
                        domainSid = sid.ToUpper();
                    }
                }
                catch (Exception e) {
                    log?.LogDebug(e, "DirectoryEntry tier: base bind failed for {Domain}", domainName);
                    return (false, null);
                }

                // RootDSE on the same bound server yields the forest root NC without a separate GC bind.
                try {
                    var rootDse = Helpers.CreateDirectoryEntry($"LDAP://{domainName}/RootDSE", config);
                    if (rootDse.TryGetProperty(LDAPProperties.RootDomainNamingContext, out var rootNc) &&
                        !string.IsNullOrEmpty(rootNc)) {
                        forestName = Helpers.DistinguishedNameToDomain(rootNc).ToUpper();
                    }
                }
                catch (Exception ex) {
                    log?.LogDebug(ex,
                        "DirectoryEntry tier: RootDSE read failed for {Domain}", domainName);
                }

                // fSMORoleOwner on the domain NC is the PDC NTDS Settings DN; its parent server
                // object carries dNSHostName. Mirrors the extraction logic in the other tiers.
                try {
                    if (root.TryGetProperty(LDAPProperties.FSMORoleOwner, out var fsmoOwner) &&
                        TryStripNtdsSettingsPrefix(fsmoOwner, out var serverDn)) {
                        var server = Helpers.CreateDirectoryEntry($"LDAP://{serverDn}", config);
                        if (server.TryGetProperty(LDAPProperties.DNSHostName, out var pdc) &&
                            !string.IsNullOrEmpty(pdc)) {
                            primaryDomainController = pdc;
                        }
                    }
                }
                catch (Exception ex) {
                    log?.LogDebug(ex,
                        "DirectoryEntry tier: PDC lookup failed for {Domain}", domainName);
                }

                return (true, new DomainInfo(
                    name: name,
                    distinguishedName: distinguishedName,
                    forestName: forestName,
                    domainSid: domainSid,
                    primaryDomainController: primaryDomainController));
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Constructs and binds a one-shot <see cref="System.DirectoryServices.Protocols.LdapConnection"/>
        /// to <paramref name="target"/> honoring every option on <paramref name="config"/> (port,
        /// SSL, signing, auth type, credentials, cert verification). This is the same configuration
        /// shape used by <c>LdapConnectionPool.CreateBaseConnection</c>, duplicated here because
        /// this code runs *outside* any pool and must not take a dependency on pool internals.
        /// </summary>
        /// <remarks>
        /// Tries SSL first then plain LDAP, respecting <see cref="LdapConfig.ForceSSL"/>: when
        /// ForceSSL is set, only the SSL attempt is made. Returns <c>null</c> if neither transport
        /// binds. The returned connection is owned by the caller and must be disposed.
        /// </remarks>
        private static LdapConnection TryBindOneShotLdapConnection(
            string target, LdapConfig config, ILogger log) {
            var transports = config.ForceSSL ? new[] { true } : new[] { true, false };
            foreach (var ssl in transports) {
                LdapConnection connection = null;
                try {
                    var port = config.GetPort(ssl);
                    var identifier = new LdapDirectoryIdentifier(
                        target, port, false, false);
                    connection = new LdapConnection(identifier) {
                        Timeout = TimeSpan.FromSeconds(30),
                    };
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.ReferralChasing =
                        ReferralChasingOptions.None;
                    if (ssl) connection.SessionOptions.SecureSocketLayer = true;

                    if (config.DisableSigning || ssl) {
                        connection.SessionOptions.Signing = false;
                        connection.SessionOptions.Sealing = false;
                    } else {
                        connection.SessionOptions.Signing = true;
                        connection.SessionOptions.Sealing = true;
                    }

                    if (config.DisableCertVerification)
                        connection.SessionOptions.VerifyServerCertificate = (_, __) => true;

                    if (config.Username != null) {
                        connection.Credential = new NetworkCredential(config.Username, config.Password);
                    }

                    connection.AuthType = config.AuthType;
                    connection.Bind();
                    return connection;
                }
                catch (Exception e) {
                    log?.LogDebug(e,
                        "TryBindOneShotLdapConnection: bind failed for {Target} ssl={Ssl}", target, ssl);
                    connection?.Dispose();
                }
            }
            return null;
        }

        /// <summary>
        /// Selects the bind target for the static one-shot LDAP path: <see cref="LdapConfig.Server"/>
        /// when explicitly set, otherwise <paramref name="domainName"/>. Mirrors the equivalent
        /// short-circuit in <c>LdapConnectionPool.CreateNewConnection</c> so both controlled tiers
        /// honor the user's <see cref="LdapConfig.Server"/> override consistently.
        /// </summary>
        internal static string ResolveOneShotBindTarget(string domainName, LdapConfig config) {
            if (config != null && !string.IsNullOrWhiteSpace(config.Server)) {
                return config.Server;
            }
            return domainName;
        }

        /// <summary>
        /// Controlled resolver used when no <see cref="ConnectionPoolManager"/> is available to
        /// route queries through. Binds a one-shot <see cref="System.DirectoryServices.Protocols.LdapConnection"/>
        /// to <see cref="LdapConfig.Server"/> when set, otherwise to <paramref name="domainName"/>
        /// (treating it as a DNS domain name that resolves to a DC via standard round-robin A/SRV
        /// records) and populates a <see cref="DomainInfo"/> by issuing the same rootDSE + Base +
        /// Subtree queries as <see cref="ResolveDomainInfoControlledAsyncCore"/>, just over a
        /// private connection.
        /// </summary>
        /// <remarks>
        /// Intended as the intermediate step in <see cref="GetDomainInfoStaticAsync"/> between the
        /// pool-based controlled path and the uncontrolled <c>Domain.GetDomain</c> fallback, so that
        /// callers inside <see cref="LdapConnectionPool"/> (which must pass <c>pool = null</c> to
        /// avoid reentering connection acquisition) still have a controlled resolution option when
        /// <see cref="LdapConfig.AllowFallbackToUncontrolledLdap"/> is off. The connection is torn
        /// down before returning; no state is added to any pool.
        /// </remarks>
        private static async Task<(bool Success, DomainInfo DomainInfo)> TryResolveDomainInfoViaDirectLdapAsync(
            string domainName, LdapConfig config, ILogger log) {
            if (string.IsNullOrWhiteSpace(domainName) || config == null) {
                return (false, null);
            }

            // Honor LdapConfig.Server the same way the pool does. The resolved DomainInfo's Name is
            // still derived from the bound DC's defaultNamingContext, so a Server pointed at a DC
            // in a different domain than domainName will yield a record whose Name does not match
            // domainName - same behavior as the pool, and the user's explicit override of intent.
            var target = ResolveOneShotBindTarget(domainName, config);
            var connection = TryBindOneShotLdapConnection(target, config, log);
            if (connection == null) {
                return (false, null);
            }

            // Offload the synchronous SendRequest calls so we don't block the calling thread when
            // called from an async code path (e.g. LdapConnectionPool.CreateLdapConnection).
            return await Task.Run(() => {
                try {
                    return ResolveDomainInfoFromConnection(connection, domainName, log);
                }
                finally {
                    connection.Dispose();
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Re-runs the direct-LDAP resolution against a DC name discovered by a sparser tier
        /// (ADSI or the uncontrolled <c>Domain.GetDomain</c> fallback) so the cached record can
        /// reach parity with the pool/one-shot tiers when the original direct-LDAP attempt
        /// failed because the domain name had no usable DNS A/SRV record from the calling host.
        /// </summary>
        /// <remarks>
        /// Skips the bind entirely when the seed already has a maximum
        /// <see cref="CompletenessScore"/>, when no bind target can be derived (no
        /// <see cref="LdapConfig.Server"/> pin, no <see cref="DomainInfo.PrimaryDomainController"/>,
        /// and an empty <see cref="DomainInfo.DomainControllers"/> list), or when every attempted
        /// bind fails. In any of these cases the original seed is returned unchanged.
        /// <para>
        /// Server pinning: when <see cref="LdapConfig.Server"/> is set the pinned host is the
        /// only enrichment target. Pinning's contract forbids fanning out to alternate DCs even
        /// when the pinned target is unreachable, so a failed bind under pinning returns the
        /// seed without trying any DC from the seed's discovery list.
        /// </para>
        /// <para>
        /// Without pinning the function walks an ordered candidate list - PDC first, then each
        /// entry of <see cref="DomainInfo.DomainControllers"/> - case-insensitively deduplicated
        /// and capped at <see cref="MaxEnrichmentBindAttempts"/> targets so a stale or oversized
        /// DC list cannot blow out call latency. The first successful resolve wins; subsequent
        /// targets are not contacted. When the retry succeeds, the merged result is selected by
        /// <see cref="SelectRicherDomainInfo"/>, which enforces the canonical-name guard so a
        /// retry that lands on a DC outside the requested domain does not poison the cache.
        /// </para>
        /// </remarks>
        internal static async Task<DomainInfo> TryEnrichDomainInfoViaDirectLdapAsync(
            string domainName, DomainInfo seed, LdapConfig config, ILogger log) {
            if (seed == null) return null;
            if (CompletenessScore(seed) >= 7 || string.IsNullOrWhiteSpace(domainName) || config == null) return seed;

            IReadOnlyList<string> candidates;
            if (!string.IsNullOrWhiteSpace(config.Server)) {
                // Pinned: never fall through to the seed's discovery list.
                candidates = new[] { config.Server };
            } else {
                var ordered = new List<string>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (!string.IsNullOrWhiteSpace(seed.PrimaryDomainController) &&
                    seen.Add(seed.PrimaryDomainController)) {
                    ordered.Add(seed.PrimaryDomainController);
                }
                if (seed.DomainControllers is { Count: > 0 }) {
                    foreach (var dc in seed.DomainControllers) {
                        if (string.IsNullOrWhiteSpace(dc) || !seen.Add(dc)) continue;
                        ordered.Add(dc);
                        if (ordered.Count >= MaxEnrichmentBindAttempts) break;
                    }
                }
                candidates = ordered;
            }

            if (candidates.Count == 0) return seed;

            foreach (var target in candidates) {
                var connection = TryBindOneShotLdapConnection(target, config, log);
                if (connection == null) {
                    log?.LogDebug(
                        "Direct LDAP enrichment bind failed for {Domain} via {Target}",
                        domainName, target);
                    continue;
                }

                var (ok, enriched) = await Task.Run(() => {
                    try {
                        return ResolveDomainInfoFromConnection(connection, domainName, log);
                    }
                    finally {
                        connection.Dispose();
                    }
                }).ConfigureAwait(false);

                if (ok) {
                    return SelectRicherDomainInfo(seed, enriched);
                }

                log?.LogDebug(
                    "Direct LDAP enrichment resolve failed for {Domain} via {Target}",
                    domainName, target);
            }

            return seed;
        }

        private const int MaxEnrichmentBindAttempts = 5;

        /// <summary>
        /// Synchronous body of <see cref="TryResolveDomainInfoViaDirectLdapAsync"/>. Uses
        /// <c>SendRequest</c> directly rather than the pool's <c>Query</c> because no pool is
        /// available on this path. Follows the same attribute shape as
        /// <see cref="ResolveDomainInfoControlledAsyncCore"/>: rootDSE → domain NC base →
        /// PDC server DN → CN=Partitions crossRef (NetBIOS) → DC subtree enumeration, each
        /// wrapped independently so a partial failure still returns a usable
        /// <see cref="DomainInfo"/>.
        /// </summary>
        private static (bool Success, DomainInfo DomainInfo) ResolveDomainInfoFromConnection(
            LdapConnection connection, string domainName, ILogger log) {
            // 1. RootDSE - the authoritative source for the default/config/root NCs of the DC we bound to.
            string defaultNc = null, configNc = null, rootNc = null;
            try {
                var rootReq = new SearchRequest(
                    "", "(objectClass=*)", SearchScope.Base,
                    new[] {
                        LDAPProperties.DefaultNamingContext,
                        LDAPProperties.ConfigurationNamingContext,
                        LDAPProperties.RootDomainNamingContext,
                    });
                var rootResp = (SearchResponse)connection.SendRequest(rootReq);
                if (rootResp?.Entries != null && rootResp.Entries.Count > 0) {
                    var entry = new SearchResultEntryWrapper(rootResp.Entries[0]);
                    entry.TryGetProperty(LDAPProperties.DefaultNamingContext, out defaultNc);
                    entry.TryGetProperty(LDAPProperties.ConfigurationNamingContext, out configNc);
                    entry.TryGetProperty(LDAPProperties.RootDomainNamingContext, out rootNc);
                }
            }
            catch (Exception e) {
                log?.LogDebug(e, "Direct LDAP rootDSE read failed for {Domain}", domainName);
                return (false, null);
            }

            if (string.IsNullOrWhiteSpace(defaultNc)) {
                return (false, null);
            }

            var derivedName = Helpers.DistinguishedNameToDomain(defaultNc);
            if (string.IsNullOrEmpty(derivedName)) return (false, null);
            var name = derivedName.ToUpper();
            string domainSid = null;
            string forestName = null;
            string primaryDomainController = null;
            string netBiosName = null;
            IReadOnlyList<string> domainControllers = null;
            if (!string.IsNullOrWhiteSpace(rootNc)) {
                var derivedForest = Helpers.DistinguishedNameToDomain(rootNc);
                if (!string.IsNullOrEmpty(derivedForest)) {
                    forestName = derivedForest.ToUpper();
                }
            }

            // 2. Domain NC base search - objectSid + fsmoRoleOwner in one round-trip.
            string fsmoOwner = null;
            try {
                var domReq = new SearchRequest(
                    defaultNc, "(objectClass=*)", SearchScope.Base,
                    new[] { LDAPProperties.ObjectSID, LDAPProperties.FSMORoleOwner });
                var domResp = (SearchResponse)connection.SendRequest(domReq);
                if (domResp?.Entries != null && domResp.Entries.Count > 0) {
                    var entry = new SearchResultEntryWrapper(domResp.Entries[0]);
                    if (entry.TryGetSecurityIdentifier(out var sid) && !string.IsNullOrEmpty(sid)) {
                        domainSid = sid.ToUpper();
                    }
                    entry.TryGetProperty(LDAPProperties.FSMORoleOwner, out fsmoOwner);
                }
            }
            catch (Exception e) {
                log?.LogDebug(e, "Direct LDAP domain NC read failed for {Domain}", domainName);
            }

            // 3. PDC server dNSHostName via the fsmoRoleOwner DN parent.
            if (TryStripNtdsSettingsPrefix(fsmoOwner, out var serverDn)) {
                try {
                    var pdcReq = new SearchRequest(
                        serverDn, "(objectClass=*)", SearchScope.Base,
                        new[] { LDAPProperties.DNSHostName });
                    var pdcResp = (SearchResponse)connection.SendRequest(pdcReq);
                    if (pdcResp?.Entries != null && pdcResp.Entries.Count > 0) {
                        var entry = new SearchResultEntryWrapper(pdcResp.Entries[0]);
                        if (entry.TryGetProperty(LDAPProperties.DNSHostName, out var pdcName)) {
                            primaryDomainController = pdcName;
                        }
                    }
                }
                catch (Exception e) {
                    log?.LogDebug(e, "Direct LDAP PDC lookup failed for {Domain}", domainName);
                }
            }

            // 4. NetBIOS name via the crossRef object under CN=Partitions whose nCName matches
            // the domain NC. Mirrors the partitions lookup in ResolveDomainInfoControlledAsyncCore
            // so the static one-shot tier produces the same field shape as the pool tier.
            if (!string.IsNullOrWhiteSpace(configNc)) {
                try {
                    var nbReq = new SearchRequest(
                        $"CN=Partitions,{configNc}",
                        $"(&(objectClass=crossRef)({LDAPProperties.NCName}={defaultNc}))",
                        SearchScope.OneLevel,
                        new[] { LDAPProperties.NetbiosName });
                    var nbResp = (SearchResponse)connection.SendRequest(nbReq);
                    if (nbResp?.Entries is { Count: > 0 }) {
                        var entry = new SearchResultEntryWrapper(nbResp.Entries[0]);
                        if (entry.TryGetProperty(LDAPProperties.NetbiosName, out var nb) &&
                            !string.IsNullOrEmpty(nb)) {
                            netBiosName = nb;
                        }
                    }
                }
                catch (Exception e) {
                    log?.LogDebug(e, "Direct LDAP netbios lookup failed for {Domain}", domainName);
                }
            }

            // 5. Domain controller enumeration - same filter as CommonFilters.DomainControllers.
            try {
                var dcs = new List<string>();
                var dcReq = new SearchRequest(
                    defaultNc, CommonFilters.DomainControllers, SearchScope.Subtree,
                    new[] { LDAPProperties.DNSHostName });
                var dcResp = (SearchResponse)connection.SendRequest(dcReq);
                if (dcResp?.Entries != null) {
                    foreach (SearchResultEntry e in dcResp.Entries) {
                        var wrap = new SearchResultEntryWrapper(e);
                        if (wrap.TryGetProperty(LDAPProperties.DNSHostName, out var dcName) &&
                            !string.IsNullOrEmpty(dcName)) {
                            dcs.Add(dcName);
                        }
                    }
                }
                domainControllers = dcs;
                if (string.IsNullOrEmpty(primaryDomainController) && dcs.Count > 0) {
                    primaryDomainController = dcs[0];
                }
            }
            catch (Exception e) {
                log?.LogDebug(e, "Direct LDAP DC enumeration failed for {Domain}", domainName);
            }

            return (true, new DomainInfo(
                name: name,
                distinguishedName: defaultNc,
                forestName: forestName,
                domainSid: domainSid,
                netBiosName: netBiosName,
                primaryDomainController: primaryDomainController,
                domainControllers: domainControllers));
        }

        public void ResetUtils() {
            _unresolvablePrincipals.Clear();
            _domainInfoCache.Clear();
            _domainControllers.Clear();
            lock (_currentDomainLock) {
                _currentDomain?.Dispose();
                _currentDomain = null;
            }
            LdapConnectionPool.ResetCaches();
            _connectionPool?.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);

            // Metrics
            LdapMetrics.ResetInFlight();
        }

        /// <summary>
        /// Computes the <c>contextName</c> and <see cref="ContextOptions"/> that should be passed
        /// to a <see cref="PrincipalContext"/> for a given <see cref="LdapConfig"/>.
        ///
        /// <para>
        /// Separated from <see cref="CreatePrincipalContext"/> so that the parameter-building logic
        /// can be unit-tested without constructing a real <see cref="PrincipalContext"/> (which
        /// would require a live directory connection).
        /// </para>
        ///
        /// <para>
        /// When <see cref="LdapConfig.Server"/> is set, the server hostname is returned as
        /// <c>contextName</c> so that <see cref="PrincipalContext"/> binds to that specific DC
        /// rather than relying on domain-level DNS discovery. Non-standard ports are expressed as
        /// <c>host:port</c>. Otherwise <paramref name="domainName"/> is returned as-is (null = let
        /// the runtime discover the current domain).
        /// </para>
        ///
        /// <para>
        /// Signing and sealing are disabled when SSL is active, mirroring the mutual-exclusion rule
        /// applied by <see cref="LdapConnectionPool.CreateBaseConnection"/>.
        /// </para>
        /// </summary>
        internal static (string ContextName, ContextOptions Options) BuildPrincipalContextParameters(
            LdapConfig config, string domainName = null) {
            var options = ContextOptions.Negotiate;

            if (config.ForceSSL) {
                options |= ContextOptions.SecureSocketLayer;
            }

            // Signing and sealing are mutually exclusive with SSL (the transport provides integrity).
            if (!config.DisableSigning && !config.ForceSSL) {
                options |= ContextOptions.Signing | ContextOptions.Sealing;
            }

            // GetServerTarget() returns null when Server is not set, so the ?? falls through to
            // domainName — which itself may be null, meaning "let the runtime discover the domain".
            var contextName = config.GetServerTarget() ?? domainName;

            return (contextName, options);
        }

        /// <summary>
        /// Creates a <see cref="PrincipalContext"/> that targets the same DC as the connection pool
        /// and applies the same SSL / signing / credential settings from <paramref name="config"/>.
        ///
        /// <para>
        /// <see cref="ContextType.Domain"/> is always used. When <see cref="LdapConfig.Server"/> is
        /// set, the server hostname is passed as the <c>name</c> argument so the runtime binds to
        /// that specific DC rather than performing domain-level DNS discovery.
        /// </para>
        ///
        /// <para>Note: <see cref="LdapConfig.DisableCertVerification"/> cannot be applied here —
        /// <see cref="PrincipalContext"/> exposes no API for it.</para>
        ///
        /// <para>This is intentionally <c>static</c> so that Moq's Castle.DynamicProxy does not
        /// encounter <see cref="PrincipalContext"/> in an instance-method signature when building
        /// test proxies against <see cref="LdapUtils"/> on non-Windows runtimes.</para>
        /// </summary>
        private static PrincipalContext CreatePrincipalContext(LdapConfig config, string domainName = null) {
            var (contextName, options) = BuildPrincipalContextParameters(config, domainName);

            if (config.Username != null) {
                return new PrincipalContext(ContextType.Domain, contextName, null, options,
                    config.Username, config.Password);
            }

            return new PrincipalContext(ContextType.Domain, contextName, null, options);
        }

        public void Dispose() {
            ResetUtils();
            _connectionPool?.Dispose();
        }

        internal static bool ResolveLabel(string objectIdentifier, string distinguishedName, string samAccountType,
            string[] objectClasses, int flags, out Label type) {
            type = Label.Base;
            if (objectIdentifier != null &&
                WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var principal)) {
                type = principal.ObjectType;
                return true;
            }

            //Override GMSA/MSA account to treat them as users for the graph
            if (objectClasses != null &&
                (objectClasses.Contains(ObjectClass.MSAClass, StringComparer.OrdinalIgnoreCase) ||
                 objectClasses.Contains(ObjectClass.GMSAClass, StringComparer.OrdinalIgnoreCase))) {
                type = Label.User;
                return true;
            }

            if (samAccountType != null) {
                var objectType = Helpers.SamAccountTypeToType(samAccountType);
                if (objectType != Label.Base) {
                    type = objectType;
                    return true;
                }
            }

            if (objectClasses == null || objectClasses.Length == 0) {
                type = Label.Base;
                return false;
            }

            if (objectClasses.Contains(ObjectClass.GroupPolicyContainerClass, StringComparer.OrdinalIgnoreCase))
                type = Label.GPO;
            else if (objectClasses.Contains(ObjectClass.OrganizationalUnitClass, StringComparer.OrdinalIgnoreCase))
                type = Label.OU;
            else if (objectClasses.Contains(ObjectClass.DomainClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Domain;
            else if (objectClasses.Contains(ObjectClass.ContainerClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Container;
            else if (objectClasses.Contains(ObjectClass.ConfigurationClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Configuration;
            else if (objectClasses.Contains(ObjectClass.PKICertificateTemplateClass, StringComparer.OrdinalIgnoreCase))
                type = Label.CertTemplate;
            else if (objectClasses.Contains(ObjectClass.PKIEnrollmentServiceClass, StringComparer.OrdinalIgnoreCase))
                type = Label.EnterpriseCA;
            else if (objectClasses.Contains(ObjectClass.CertificationAuthorityClass,
                         StringComparer.OrdinalIgnoreCase)) {
                if (distinguishedName.IndexOf(DirectoryPaths.RootCALocation, StringComparison.OrdinalIgnoreCase) >= 0)
                    type = Label.RootCA;
                if (distinguishedName.IndexOf(DirectoryPaths.AIACALocation, StringComparison.OrdinalIgnoreCase) >= 0)
                    type = Label.AIACA;
                if (distinguishedName.IndexOf(DirectoryPaths.NTAuthStoreLocation, StringComparison.OrdinalIgnoreCase) >=
                    0)
                    type = Label.NTAuthStore;
            }
            else if (objectClasses.Contains(ObjectClass.OIDContainerClass, StringComparer.OrdinalIgnoreCase)) {
                if (distinguishedName.StartsWith(DirectoryPaths.OIDContainerLocation,
                        StringComparison.OrdinalIgnoreCase))
                    type = Label.Container;
                else if (flags == 2) {
                    type = Label.IssuancePolicy;
                }
            }

            return type != Label.Base;
        }

        public static async Task<(bool Success, ResolvedSearchResult ResolvedResult)> ResolveSearchResult(
            IDirectoryObject directoryObject, ILdapUtils utils) {
            if (!directoryObject.GetObjectIdentifier(out var objectIdentifier)) {
                return (false, default);
            }

            var res = new ResolvedSearchResult {
                ObjectId = objectIdentifier
            };

            //If the object is deleted, we can short circuit the rest of this logic as we don't really care about anything else
            if (directoryObject.IsDeleted()) {
                res.Deleted = true;
                return (true, res);
            }

            if (directoryObject.TryGetLongProperty(LDAPProperties.UserAccountControl, out var rawUac)) {
                var flags = (UacFlags)rawUac;
                if (flags.HasFlag(UacFlags.ServerTrustAccount)) {
                    res.IsDomainController = true;
                    utils.AddDomainController(objectIdentifier);
                }
            }

            string domain;

            if (directoryObject.TryGetDistinguishedName(out var distinguishedName)) {
                domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            }
            else {
                if (objectIdentifier.StartsWith("S-1-5") &&
                    await utils.GetDomainNameFromSid(objectIdentifier) is (true, var domainName)) {
                    domain = domainName;
                }
                else {
                    return (false, default);
                }
            }

            string domainSid;
            var match = SIDRegex.Match(objectIdentifier);
            if (match.Success) {
                domainSid = match.Groups[1].Value;
            }
            else if (await utils.GetDomainSidFromDomainName(domain) is (true, var sid)) {
                domainSid = sid;
            }
            else {
                Logging.Logger.LogWarning("Failed to resolve domain sid for object {Identifier}", objectIdentifier);
                domainSid = null;
            }

            res.Domain = domain;
            res.DomainSid = domainSid;

            if (WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var wellKnownPrincipal)) {
                res.DisplayName = $"{wellKnownPrincipal.ObjectIdentifier}@{domain}";
                res.ObjectType = wellKnownPrincipal.ObjectType;
                if (await utils.GetWellKnownPrincipal(objectIdentifier, domain) is (true, var convertedPrincipal)) {
                    res.ObjectId = convertedPrincipal.ObjectIdentifier;
                }

                return (true, res);
            }

            res.ObjectType = await ComputeLabel(directoryObject, objectIdentifier, domain, utils);

            directoryObject.TryGetProperty(LDAPProperties.SAMAccountName, out var samAccountName);
            res.DisplayName = ComputeDisplayName(directoryObject, domain, res.ObjectType, samAccountName);
            return (true, res);
        }

        private static async Task<Label> ComputeLabel(IDirectoryObject directoryObject, string objectIdentifier,
            string domain, ILdapUtils utils) {
            if (!directoryObject.GetLabel(out var label)) {
                if (await utils.ResolveIDAndType(objectIdentifier, domain) is (true, var typedPrincipal)) {
                    label = typedPrincipal.ObjectType;
                }
            }

            if (directoryObject.IsMSA() || directoryObject.IsGMSA()) {
                label = Label.User;
            }

            return label;
        }

        private static string ComputeDisplayName(IDirectoryObject directoryObject, string domain, Label label,
            string samAccountName) {
            string displayName;
            switch (label) {
                case Label.User:
                case Label.Group:
                case Label.Base:
                    if (!string.IsNullOrWhiteSpace(samAccountName)) {
                        displayName = $"{samAccountName}@{domain}";
                    }
                    else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName, out var canonicalName)) {
                        displayName = $"{canonicalName}@{domain}";
                    }
                    else if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                        displayName = $"{name}@{domain}";
                    }
                    else {
                        displayName = $"UNKNOWN@{domain}";
                    }
                    break;
                case Label.Computer: {
                        var shortName = samAccountName?.TrimEnd('$');
                        if (directoryObject.TryGetProperty(LDAPProperties.DNSHostName, out var dns)) {
                            displayName = dns;
                        }
                        else if (!string.IsNullOrWhiteSpace(shortName)) {
                            displayName = $"{shortName}.{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                       out var canonicalName)) {
                            displayName = $"{canonicalName}.{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}.{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN.{domain}";
                        }

                        break;
                    }
                case Label.GPO:
                case Label.IssuancePolicy: {
                        if (directoryObject.TryGetProperty(LDAPProperties.DisplayName, out var ldapDisplayName)) {
                            displayName = $"{ldapDisplayName}@{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                       out var canonicalName)) {
                            displayName = $"{canonicalName}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                case Label.Domain:
                    displayName = domain;
                    break;
                case Label.OU: {
                        if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}@{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.OU, out var ou)) {
                            displayName = $"{ou}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                case Label.Container: {
                        if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}@{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                       out var canonicalName)) {
                            displayName = $"{canonicalName}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                case Label.Configuration:
                case Label.RootCA:
                case Label.AIACA:
                case Label.NTAuthStore:
                case Label.EnterpriseCA:
                case Label.CertTemplate: {
                        if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return displayName.ToUpper();
        }
    }
}
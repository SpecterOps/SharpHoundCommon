using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
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
using SharpHoundRPC.PortScanner;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib {
    public class LdapUtils : ILdapUtils {
        // Domain object cache keyed by domain SID. Static to share across instances (original behaviour).
        private static ConcurrentDictionary<string, Domain> _domainCache = new();

        // Forest-name cache keyed by domain name. Static + readonly to share across instances.
        private static readonly ConcurrentDictionary<string, string> DomainToForestCache =
            new(StringComparer.OrdinalIgnoreCase);

        // Unique sentinel key used to cache the result of GetDomain(out domain) (the "current" domain).
        private readonly string _nullCacheKey = Guid.NewGuid().ToString();

        private static readonly Regex SIDRegex = new(@"^(S-\d+-\d+-\d+-\d+-\d+-\d+)(-\d+)?$");

        // Used by GetDomainSidFromDomainName as fallback account name hints.
        private readonly string[] _translateNames = { "Administrator", "admin" };

        private LdapConfig _ldapConfig = new();
        private ConnectionPoolManager _connectionPool;

        // Injected infrastructure
        private readonly IMetricRouter _metric;
        private readonly ILogger _log;
        private readonly IPortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;

        // Focused service classes that own extracted responsibilities
        private readonly DomainControllerRegistry _domainControllerRegistry;
        private readonly WellKnownPrincipalService _wkpService;
        private PrincipalResolver _principalResolver;
        private readonly HostResolver _hostResolver;

        public LdapUtils() {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
            _metric = Metrics.Factory.CreateMetricRouter();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, _log);
            _domainControllerRegistry = new DomainControllerRegistry();
            // Pass 'this' so that virtual-method overrides (e.g. via Moq) are respected.
            _wkpService = new WellKnownPrincipalService(this, _domainControllerRegistry, _log);
            _principalResolver = new PrincipalResolver(this, _wkpService, _domainControllerRegistry, _ldapConfig, _log, _metric);
            _hostResolver = new HostResolver(_principalResolver, _portScanner, _nativeMethods, _log);
        }

        public LdapUtils(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null, IMetricRouter metric = null) {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
            _metric = metric ?? Metrics.Factory.CreateMetricRouter();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
            _domainControllerRegistry = new DomainControllerRegistry();
            _wkpService = new WellKnownPrincipalService(this, _domainControllerRegistry, _log);
            _principalResolver = new PrincipalResolver(this, _wkpService, _domainControllerRegistry, _ldapConfig, _log, _metric);
            _hostResolver = new HostResolver(_principalResolver, _portScanner, _nativeMethods, _log);
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

        // ── Principal resolution ──────────────────────────────────────────────────

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(
            SecurityIdentifier securityIdentifier, string objectDomain) {
            return await _principalResolver.ResolveIDAndType(securityIdentifier.Value, objectDomain);
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(
            string identifier, string objectDomain) {
            return await _principalResolver.ResolveIDAndType(identifier, objectDomain);
        }

        // ── Well-known principal resolution ───────────────────────────────────────

        public async Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
            string securityIdentifier, string objectDomain) {
            return await _wkpService.GetWellKnownPrincipal(securityIdentifier, objectDomain);
        }

        public virtual async Task<(bool Success, string ForestName)> GetForest(string domain) {
            if (DomainToForestCache.TryGetValue(domain, out var cachedForest)) {
                return (true, cachedForest);
            }

            if (GetDomain(domain, out var domainObject)) {
                try {
                    var forestName = domainObject.Forest.Name.ToUpper();
                    DomainToForestCache.TryAdd(domain, forestName);
                    return (true, forestName);
                }
                catch {
                    //pass
                }
            }

            var (success, forest) = await GetForestFromLdap(domain);
            if (success) {
                DomainToForestCache.TryAdd(domain, forest);
                return (true, forest);
            }

            return (false, null);
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
                var entry = CreateDirectoryEntry($"LDAP://<SID={domainSid}>");
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
                using (var ctx = new PrincipalContext(ContextType.Domain)) {
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
            if (!GetDomain(out var domain) || domain?.Name == null) {
                return (false, string.Empty);
            }

            var result = await Query(new LdapQueryParameters {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddDomains(CommonFilters.SpecificSID(domainSid)).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetDistinguishedName(out var distinguishedName)) {
                return (true, Helpers.DistinguishedNameToDomain(distinguishedName));
            }

            result = await Query(new LdapQueryParameters {
                DomainName = domain.Name,
                Attributes = new[] { LDAPProperties.DistinguishedName, LDAPProperties.Name },
                GlobalCatalog = true,
                LDAPFilter = new LdapFilter().AddFilter("(objectclass=trusteddomain)", true)
                    .AddFilter($"(securityidentifier={Helpers.ConvertSidToHexSid(domainSid)})", true).GetFilter()
            }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

            if (result.IsSuccess && result.Value.TryGetProperty(LDAPProperties.Name, out var domainName)) {
                return (true, domainName.ToUpper());
            }

            result = await Query(new LdapQueryParameters {
                DomainName = domain.Name,
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

            try {
                var entry = CreateDirectoryEntry($"LDAP://{domainName}");
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

            if (GetDomain(domainName, out var domainObject))
                try {
                    var entry = domainObject.GetDirectoryEntry().ToDirectoryObject();
                    if (entry.TryGetSecurityIdentifier(out domainSid)) {
                        Cache.AddDomainSidMapping(domainName, domainSid);
                        return (true, domainSid);
                    }
                }
                catch {
                    //we expect this to fail sometimes (not sure why, but better safe than sorry)
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
            var cacheKey = domainName ?? _nullCacheKey;
            if (_domainCache.TryGetValue(cacheKey, out domain)) return true;

            try {
                DirectoryContext context;
                if (_ldapConfig.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                            _ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                            _ldapConfig.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                // Blocking External Call
                domain = Domain.GetDomain(context);
                if (domain == null) return false;
                _domainCache.TryAdd(cacheKey, domain);
                return true;
            }
            catch (Exception e) {
                _log.LogDebug(e, "GetDomain call failed for domain name {Name}", domainName);
                domain = null;
                return false;
            }
        }

        public static bool GetDomain(string domainName, LdapConfig ldapConfig, out Domain domain) {
            if (_domainCache.TryGetValue(domainName, out domain)) return true;

            try {
                DirectoryContext context;
                if (ldapConfig.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, ldapConfig.Username,
                            ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, ldapConfig.Username,
                            ldapConfig.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                // Blocking External Call
                domain = Domain.GetDomain(context);
                if (domain == null) return false;
                _domainCache.TryAdd(domainName, domain);
                return true;
            }
            catch (Exception e) {
                Logging.Logger.LogDebug("Static GetDomain call failed for domain {DomainName}: {Error}", domainName,
                    e.Message);
                domain = null;
                return false;
            }
        }

        /// <summary>
        ///     Attempts to get the Domain object representing the target domain. If null is specified for the domain name, gets
        ///     the user's current domain
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public bool GetDomain(out Domain domain) {
            if (_domainCache.TryGetValue(_nullCacheKey, out domain)) return true;

            try {
                var context = _ldapConfig.Username != null
                    ? new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                        _ldapConfig.Password)
                    : new DirectoryContext(DirectoryContextType.Domain);

                // Blocking External Call
                domain = Domain.GetDomain(context);
                _domainCache.TryAdd(_nullCacheKey, domain);
                return true;
            }
            catch (Exception e) {
                _log.LogDebug(e, "GetDomain call failed for blank domain");
                domain = null;
                return false;
            }
        }

        // ── Account / host resolution ─────────────────────────────────────────────

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain) {
            return await _principalResolver.ResolveAccountName(name, domain);
        }

        public async Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain) {
            return await _hostResolver.ResolveHostToSid(host, domain);
        }

        public async Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain) {
            return await _principalResolver.GetGlobalCatalogMatches(name, domain);
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(
            string propertyValue, string propertyName, string domainName) {
            return await _principalResolver.ResolveCertTemplateByProperty(propertyValue, propertyName, domainName);
        }

        /// <summary>Created for testing purposes.</summary>
        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor() {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        // ── Local / domain controller helpers ────────────────────────────────────

        public async Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(
            SecurityIdentifier sid, string computerDomainSid, string computerDomain) {
            return await _wkpService.ConvertLocalWellKnownPrincipal(sid, computerDomainSid, computerDomain);
        }

        public async Task<bool> IsDomainController(string computerObjectId, string domainName) {
            return await _principalResolver.IsDomainController(computerObjectId, domainName);
        }

        public async Task<(bool Success, TypedPrincipal Principal)> ResolveDistinguishedName(
            string distinguishedName) {
            return await _principalResolver.ResolveDistinguishedName(distinguishedName);
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

        // ── Domain controller tracking ────────────────────────────────────────────

        public void AddDomainController(string domainControllerSID) {
            _principalResolver.AddDomainController(domainControllerSID);
        }

        // ── WKP output generation ─────────────────────────────────────────────────

        public IAsyncEnumerable<OutputBase> GetWellKnownPrincipalOutput() {
            return _wkpService.GetWellKnownPrincipalOutput();
        }

        // ── Configuration / lifecycle ─────────────────────────────────────────────

        public void SetLdapConfig(LdapConfig config) {
            _ldapConfig = config;
            _log.LogInformation("New LDAP Config Set:\n {ConfigString}", config.ToString());
            _connectionPool.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
            // Propagate new credentials so the fallback DirectoryEntry calls use them.
            _principalResolver.UpdateConfig(config);
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
                var entry = CreateDirectoryEntry($"LDAP://{domain}/RootDSE");
                if (entry.TryGetProperty(property, out var searchBase)) {
                    return (true, searchBase);
                }
            }
            catch {
                //pass
            }

            if (GetDomain(domain, out var domainObj)) {
                try {
                    var entry = domainObj.GetDirectoryEntry().ToDirectoryObject();
                    if (entry.TryGetProperty(property, out var searchBase)) {
                        return (true, searchBase);
                    }
                }
                catch {
                    //pass
                }

                var name = domainObj.Name;
                if (!string.IsNullOrWhiteSpace(name)) {
                    var tempPath = Helpers.DomainNameToDistinguishedName(name);

                    var searchBase = context switch {
                        NamingContext.Configuration => $"CN=Configuration,{tempPath}",
                        NamingContext.Schema => $"CN=Schema,CN=Configuration,{tempPath}",
                        NamingContext.Default => tempPath,
                        _ => throw new ArgumentOutOfRangeException()
                    };

                    return (true, searchBase);
                }
            }

            return (false, default);
        }

        public void ResetUtils() {
            // Reset static domain-name caches owned by LdapUtils itself.
            _domainCache = new ConcurrentDictionary<string, Domain>();

            // Delegate resets to the owning service classes.
            _principalResolver.Reset();
            _domainControllerRegistry.Reset();

            // Recreate the connection pool.
            _connectionPool?.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);

            // Rebuild the PrincipalResolver so it picks up the new connection pool reference
            // via ILdapUtils.Query which routes through the updated _connectionPool.
            _principalResolver = new PrincipalResolver(this, _wkpService, _domainControllerRegistry,
                _ldapConfig, _log, _metric);

            // Metrics
            LdapMetrics.ResetInFlight();
        }

        private IDirectoryObject CreateDirectoryEntry(string path) {
            if (_ldapConfig.Username != null) {
                return new DirectoryEntry(path, _ldapConfig.Username, _ldapConfig.Password).ToDirectoryObject();
            }

            return new DirectoryEntry(path).ToDirectoryObject();
        }

        public void Dispose() {
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
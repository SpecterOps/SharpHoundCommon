using System;
using System.Collections.Concurrent;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.LDAPQueries;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib {
    public partial class LdapUtils {
        //This cache is indexed by domain sid
        private static ConcurrentDictionary<string, Domain> _domainCache = new();
        private static readonly ConcurrentDictionary<string, string> DomainToForestCache =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly string _nullCacheKey = Guid.NewGuid().ToString();
        private readonly string[] _translateNames = { "Administrator", "admin" };

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

    }
}

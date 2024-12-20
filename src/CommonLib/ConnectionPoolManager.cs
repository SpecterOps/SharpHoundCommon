using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.PortScanner;

namespace SharpHoundCommonLib {
    internal class ConnectionPoolManager : IDisposable{
        private readonly ConcurrentDictionary<string, LdapConnectionPool> _pools = new();
        private readonly LdapConfig _ldapConfig;
        private readonly string[] _translateNames = { "Administrator", "admin" };
        private readonly ConcurrentDictionary<string, string> _resolvedIdentifiers = new(StringComparer.OrdinalIgnoreCase);
        private readonly ILogger _log;
        private readonly IPortScanner _portScanner;

        public ConnectionPoolManager(LdapConfig config, ILogger log = null, IPortScanner scanner = null) {
            _ldapConfig = config;
            _log = log ?? Logging.LogProvider.CreateLogger("ConnectionPoolManager");
            _portScanner = scanner;
        }

        public IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
            string attributeName, CancellationToken cancellationToken = new()) {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            if (!GetPool(domain, out var pool)) {
                return new List<Result<string>> {Result<string>.Fail("Failed to resolve a connection pool")}.ToAsyncEnumerable();
            }

            return pool.RangedRetrieval(distinguishedName, attributeName, cancellationToken);
        }

        public IAsyncEnumerable<LdapResult<IDirectoryObject>> PagedQuery(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new()) {
            if (!GetPool(queryParameters.DomainName, out var pool)) {
                return new List<LdapResult<IDirectoryObject>> {LdapResult<IDirectoryObject>.Fail("Failed to resolve a connection pool", queryParameters)}.ToAsyncEnumerable();
            }

            return pool.PagedQuery(queryParameters, cancellationToken);
        }

        public IAsyncEnumerable<LdapResult<IDirectoryObject>> Query(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new()) {
            if (!GetPool(queryParameters.DomainName, out var pool)) {
                return new List<LdapResult<IDirectoryObject>> {LdapResult<IDirectoryObject>.Fail("Failed to resolve a connection pool", queryParameters)}.ToAsyncEnumerable();
            }

            return pool.Query(queryParameters, cancellationToken);
        }

        public void ReleaseConnection(LdapConnectionWrapper connectionWrapper, bool connectionFaulted = false) {
            if (connectionWrapper == null) {
                return;
            }
            //I don't think this is possible, but at least account for it
            if (!_pools.TryGetValue(connectionWrapper.PoolIdentifier, out var pool)) {
                _log.LogWarning("Could not find pool for {Identifier}", connectionWrapper.PoolIdentifier);
                connectionWrapper.Connection.Dispose();
                return;
            }
        
            pool.ReleaseConnection(connectionWrapper, connectionFaulted);
        }

        public async Task<(bool Success, string Message)> TestDomainConnection(string identifier, bool globalCatalog) {
            var (success, connection, message) = await GetLdapConnection(identifier, globalCatalog);
            ReleaseConnection(connection);
            return (success, message);
        }

        private bool GetPool(string identifier, out LdapConnectionPool pool) {
            if (identifier == null) {
                pool = default;
                return false;
            }

            var resolved = ResolveIdentifier(identifier);
            if (!_pools.TryGetValue(resolved, out pool)) {
                pool = new LdapConnectionPool(identifier, resolved, _ldapConfig,scanner: _portScanner);
                _pools.TryAdd(resolved, pool);
            }

            return true;
        }

        public async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)> GetLdapConnection(
            string identifier, bool globalCatalog) {
            if (!GetPool(identifier, out var pool)) {
                return (false, default, $"Unable to resolve a pool for {identifier}");
            }

            if (globalCatalog) {
                return await pool.GetGlobalCatalogConnectionAsync();
            }
            return await pool.GetConnectionAsync();
        }
    
        public (bool Success, LdapConnectionWrapper connectionWrapper, string Message) GetLdapConnectionForServer(
            string identifier, string server, bool globalCatalog) {
            if (!GetPool(identifier, out var pool)) {
                return (false, default, $"Unable to resolve a pool for {identifier}");
            }
        
            return pool.GetConnectionForSpecificServerAsync(server, globalCatalog);
        }

        private string ResolveIdentifier(string identifier) {
            if (_resolvedIdentifiers.TryGetValue(identifier, out var resolved)) {
                return resolved;
            }
            
            if (GetDomainSidFromDomainName(identifier, out var sid)) {
                _log.LogDebug("Resolved identifier {Identifier} to {Resolved}", identifier, sid);
                _resolvedIdentifiers.TryAdd(identifier, sid);
                return sid;
            }
            
            return identifier;
        }
    
        private bool GetDomainSidFromDomainName(string domainName, out string domainSid) {
            if (Cache.GetDomainSidMapping(domainName, out domainSid)) return true;

            try {
                var entry = new DirectoryEntry($"LDAP://{domainName}").ToDirectoryObject();
                if (entry.TryGetSecurityIdentifier(out var sid)) {
                    Cache.AddDomainSidMapping(domainName, sid);
                    domainSid = sid;
                    return true;
                }
            }
            catch {
                //we expect this to fail sometimes
            }

            if (LdapUtils.GetDomain(domainName, _ldapConfig, out var domainObject))
                try {
                    if (domainObject.GetDirectoryEntry().ToDirectoryObject().TryGetSecurityIdentifier(out domainSid)) {
                        Cache.AddDomainSidMapping(domainName, domainSid);
                        return true;
                    }
                }
                catch {
                    //we expect this to fail sometimes (not sure why, but better safe than sorry)
                }

            foreach (var name in _translateNames)
                try {
                    var account = new NTAccount(domainName, name);
                    var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    domainSid = sid.AccountDomainSid.ToString();
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return true;
                }
                catch {
                    //We expect this to fail if the username doesn't exist in the domain
                }

            return false;
        }

        public void Dispose() {
            foreach (var kv in _pools)
            {
                kv.Value.Dispose();
            }
        
            _pools.Clear();
        }
    }
}
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
            _portScanner = scanner ?? new PortScanner();
        }

        public IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
            string attributeName, CancellationToken cancellationToken = new()) {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            var (getPoolSuccess, pool) = GetPool(domain);
            if (!getPoolSuccess) {
                return new List<Result<string>> {Result<string>.Fail("Failed to resolve a connection pool")}.ToAsyncEnumerable();
            }

            return pool.RangedRetrieval(distinguishedName, attributeName, cancellationToken);
        }

        public IAsyncEnumerable<LdapResult<IDirectoryObject>> PagedQuery(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new()) {
            var (getPoolSuccess, pool) = GetPool(queryParameters.DomainName);
            if (!getPoolSuccess) {
                return new List<LdapResult<IDirectoryObject>> {LdapResult<IDirectoryObject>.Fail("Failed to resolve a connection pool", queryParameters)}.ToAsyncEnumerable();
            }

            return pool.PagedQuery(queryParameters, cancellationToken);
        }

        public IAsyncEnumerable<LdapResult<IDirectoryObject>> Query(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new()) {
            var (getPoolSuccess, pool) = GetPool(queryParameters.DomainName);
            if (!getPoolSuccess) {
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

        private (bool, LdapConnectionPool) GetPool(string identifier) {
            if (string.IsNullOrWhiteSpace(identifier)) {
                return (false, default);
            }

            var resolved = ResolveIdentifier(identifier);
            var pool = _pools.GetOrAdd(resolved, _ => new LdapConnectionPool(identifier, resolved, _ldapConfig, scanner: _portScanner));
            
            return (true, pool);
        }

        public async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)> GetLdapConnection(
            string identifier, bool globalCatalog) {
            var (getPoolSuccess, pool) = GetPool(identifier);
            if (!getPoolSuccess) {
                return (false, default, $"Unable to resolve a pool for {identifier}");
            }

            if (globalCatalog) {
                return await pool.GetGlobalCatalogConnectionAsync();
            }

            return await pool.GetConnectionAsync();
        }
    
        public (bool Success, LdapConnectionWrapper connectionWrapper, string Message) GetLdapConnectionForServer(
            string identifier, string server, bool globalCatalog) {
            
            return GetLdapConnectionForServerAsync(identifier, server, globalCatalog).GetAwaiter().GetResult();
        }
        
        public async Task<(bool Success, LdapConnectionWrapper connectionWrapper, string Message)> GetLdapConnectionForServerAsync(
            string identifier, string server, bool globalCatalog) {
            var (getPoolSuccess, pool) = GetPool(identifier);
            if (!getPoolSuccess) {
                return (false, default, $"Unable to resolve a pool for {identifier}");
            }
        
            return await pool.GetConnectionForSpecificServerActuallyAsync(server, globalCatalog);
        }

        private string ResolveIdentifier(string identifier) {
            if (_resolvedIdentifiers.TryGetValue(identifier, out var resolved)) {
                return resolved;
            }

            if (GetDomainSidFromDomainName(identifier) is (true, var sid)) {
                _log.LogDebug("Resolved identifier {Identifier} to {Resolved}", identifier, sid);
                _resolvedIdentifiers.TryAdd(identifier, sid);
                return sid;
            }

            return identifier;
        }
    
        private (bool, string) GetDomainSidFromDomainName(string domainName) {
            if (Cache.GetDomainSidMapping(domainName, out var domainSid)) return (true, domainSid);

            // Controlled replacement for LdapUtils.GetDomain + GetDirectoryEntry. We pass pool: null
            // because this method is called from inside GetPool -> ResolveIdentifier while resolving
            // the pool for this same domain; reusing the pool here would reenter GetLdapConnection and
            // recurse into GetDomainSidFromDomainName. With pool: null, GetDomainInfoStaticAsync falls
            // through to its direct-LDAP (one-shot LdapConnection) path, which still honors LdapConfig.
            // The call is sync-over-async to match the sibling pattern in GetLdapConnectionForServer.
            // Tried before the legacy ADSI bind so that uncontrolled/serverless ADSI lookups do not
            // run prior to ResolveIdentifier/GetPool/GetLdapConnectionForServer logic.
            var (infoOk, info) = LdapUtils
                .GetDomainInfoStaticAsync(domainName, _ldapConfig, _log)
                .GetAwaiter().GetResult();
            if (infoOk && !string.IsNullOrEmpty(info?.DomainSid)) {
                Cache.AddDomainSidMapping(domainName, info.DomainSid);
                return (true, info.DomainSid);
            }

            try {
                var entry = Helpers.CreateDirectoryEntry($"LDAP://{domainName}", _ldapConfig);
                if (entry.TryGetSecurityIdentifier(out var sid)) {
                    Cache.AddDomainSidMapping(domainName, sid);
                    return (true, sid);
                }
            }
            catch {
                //we expect this to fail sometimes
            }

            foreach (var name in _translateNames)
                try {
                    var account = new NTAccount(domainName, name);
                    // Blocking External Call
                    // Calls Win32.LsaOpenPolicy and either Win32NativeLsaLookupNames2 or Win32Native.LsaLookupNames
                    var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    domainSid = sid.AccountDomainSid.ToString();
                    Cache.AddDomainSidMapping(domainName, domainSid);
                    return (true, domainSid);
                }
                catch {
                    //We expect this to fail if the username doesn't exist in the domain
                }

            return (false, null);
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
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.Static;
using SharpHoundRPC.PortScanner;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;

namespace SharpHoundCommonLib {
    // Responsibility-specific behavior is organized in the LdapUtils partial-class files.
    public partial class LdapUtils : ILdapUtils {
        private readonly ILogger _log;
        private LdapConfig _ldapConfig = new();

        private ConnectionPoolManager _connectionPool;

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

        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor() {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        public void SetLdapConfig(LdapConfig config) {
            _ldapConfig = config;
            _log.LogInformation("New LDAP Config Set:\n {ConfigString}", config.ToString());
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
            _unresolvablePrincipals = new ConcurrentHashSet(StringComparer.OrdinalIgnoreCase);
            _domainCache = new ConcurrentDictionary<string, Domain>();
            _domainControllers = new ConcurrentHashSet(StringComparer.OrdinalIgnoreCase);
            _connectionPool?.Dispose();
            _connectionPool = new ConnectionPoolManager(_ldapConfig, scanner: _portScanner);
            
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
    }
}

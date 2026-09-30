using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib {
    // Resolves domain identity directly from LDAP. Do not use LdapUtils or the pools here:
    // pool initialization itself needs domain resolution and would recurse back into this code.
    internal sealed class LdapDomainResolver {
        // Creates an unbound connection owned and disposed by the resolver.
        internal delegate IConnection ConnectionFactory(string target, bool ssl, bool pinServer);

        // Reads the USERDNSDOMAIN endpoint hint when no explicit target or UserDomain hint is available.
        internal delegate string EnvironmentDomainReader();

        private readonly LdapConfig _config;
        private readonly ILogger _log;
        private readonly ConnectionFactory _createConnection;
        private readonly EnvironmentDomainReader _getEnvironmentDomain;

        // The shared factory preserves LDAP settings and leaves credentials unset when no
        // username is configured, allowing the bind to use ambient outbound credentials.
        internal LdapDomainResolver(LdapConfig config, ILogger log = null)
            : this(config, (target, ssl, pinServer) =>
                new Connection(LdapConnectionFactory.Create(config, target, ssl, pinServer: pinServer)),
                () => Environment.GetEnvironmentVariable("USERDNSDOMAIN"), log) { }

        // These delegates keep connection failures and environment hints testable without AD
        // access or changes to process-wide environment variables.
        internal LdapDomainResolver(LdapConfig config,
            ConnectionFactory createConnection, EnvironmentDomainReader getEnvironmentDomain,
            ILogger log = null) {
            _config = config;
            _createConnection = createConnection;
            _getEnvironmentDomain = getEnvironmentDomain;
            _log = log ?? Logging.LogProvider.CreateLogger("LdapDomainResolver");
        }

        /// <summary>
        /// Resolves a domain name and default naming context; additional naming contexts may be null.
        /// Returns false with a null result when the target cannot establish the requested identity.
        /// </summary>
        internal bool TryResolve(string domainName, out LdapDomainInfo domain) {
            domain = null;
            var suppliedDomain = Normalize(domainName);
            var server = Normalize(_config.Server);
            // A configured server selects the endpoint, but does not override validation of
            // an explicitly supplied domain. USERDNSDOMAIN is only a last-resort endpoint hint.
            var target = server ?? suppliedDomain;
            if (target == null) {
                // UserDomain describes the credential domain, which can differ from the local
                // logon environment under /netonly. It guides discovery without changing credentials
                // or constraining the domain advertised by a configured server.
                target = Normalize(_config.UserDomain);
            }
            if (target == null) {
                target = Normalize(_getEnvironmentDomain());
            }
            if (target == null) return false;

            // Pinning disables referrals and automatic reconnection in the shared factory.
            // Both protocol attempts and every search must retain this configured host.
            var pinServer = server != null;
            try {
                using (var connection = _createConnection(target, ssl: true, pinServer: pinServer)) {
                    connection.Bind();
                    // A mismatch or missing core data is definitive; do not retry over plaintext.
                    return TryReadIdentity(connection, suppliedDomain, out domain);
                }
            }
            catch (Exception e) when (e is LdapException || e is DirectoryOperationException ||
                                      e is InvalidOperationException || e is ArgumentException) {
                domain = null;
                _log.LogDebug(e, "Controlled domain resolution failed for endpoint {Endpoint} using SSL {SSL}",
                    target, true);
            }

            if (_config.ForceSSL) return false;

            // The SSL operation failed and plaintext is permitted. Keep the same endpoint.
            try {
                using (var connection = _createConnection(target, ssl: false, pinServer: pinServer)) {
                    connection.Bind();
                    return TryReadIdentity(connection, suppliedDomain, out domain);
                }
            }
            catch (Exception e) when (e is LdapException || e is DirectoryOperationException ||
                                      e is InvalidOperationException || e is ArgumentException) {
                domain = null;
                _log.LogDebug(e, "Controlled domain resolution failed for endpoint {Endpoint} using SSL {SSL}",
                    target, false);
            }

            return false;
        }

        private bool TryReadIdentity(IConnection connection, string suppliedDomain,
            out LdapDomainInfo domain) {
            domain = null;
            // RootDSE is the server's naming-context advertisement. The empty DN and base
            // scope address that entry without needing to know a domain search base first.
            var rootDseRequest = new SearchRequest("", "(objectClass=*)", SearchScope.Base,
                "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
                "schemaNamingContext");
            var entries = connection.Search(rootDseRequest);
            if (entries.Count != 1) return false;

            var root = entries[0];
            var defaultNamingContext = ReadString(root, "defaultNamingContext");
            // Derive the identity from the returned DN, rather than assuming the endpoint
            // or environment hint names the domain actually served by this connection.
            var domainName = DomainFromNamingContext(defaultNamingContext);
            if (domainName == null) return false;

            var configurationNamingContext = ReadString(root, "configurationNamingContext");
            if (!MatchesSuppliedDomain(connection, suppliedDomain, domainName, defaultNamingContext,
                    configurationNamingContext)) {
                return false;
            }

            // Only the default naming context and its domain name are required for success.
            // Missing forest, configuration, or schema metadata must preserve that success.
            domain = new LdapDomainInfo {
                Name = domainName,
                DefaultNamingContext = defaultNamingContext,
                ForestName = DomainFromNamingContext(ReadString(root, "rootDomainNamingContext")),
                ConfigurationNamingContext = configurationNamingContext,
                SchemaNamingContext = ReadString(root, "schemaNamingContext")
            };
            ReadAdditionalMetadata(connection, domain);
            return true;
        }

        private void ReadAdditionalMetadata(IConnection connection, LdapDomainInfo domain) {
            IDirectoryObject domainRoot = null;
            ReadOptionalMetadata(domain.Name, "domain root", () => {
                var entries = connection.Search(new SearchRequest(domain.DefaultNamingContext,
                    "(objectClass=*)", SearchScope.Base, "objectSid", "fSMORoleOwner"));
                if (entries.Count == 1) domainRoot = entries[0];
            });

            if (domainRoot != null) {
                // SID conversion and the PDC lookup are independent: malformed or unreadable
                // metadata in either must not prevent the other from being materialized.
                ReadOptionalMetadata(domain.Name, "domain SID", () => {
                    if (domainRoot.TryGetSecurityIdentifier(out var sid)) domain.DomainSid = Normalize(sid);
                });
                ReadOptionalMetadata(domain.Name, "PDC hostname", () =>
                    domain.PdcRoleOwnerName = ReadPdcHostname(connection, domainRoot));
            }

            ReadOptionalMetadata(domain.Name, "controller hostnames", () => {
                // Publish only a complete search; a later-page failure leaves the list empty.
                domain.DomainControllerNames.AddRange(ReadControllerNames(connection, domain.DefaultNamingContext));
            });
            ReadTrustMetadata(connection, domain);
        }

        private void ReadTrustMetadata(IConnection connection, LdapDomainInfo domain) {
            var topology = new Dictionary<string, IDirectoryObject>(StringComparer.OrdinalIgnoreCase);
            if (domain.ConfigurationNamingContext != null) {
                ReadOptionalMetadata(domain.Name, "domain trust topology", () => {
                    var request = new SearchRequest("CN=Partitions," + domain.ConfigurationNamingContext,
                        "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
                        SearchScope.OneLevel, "nCName", "trustParent", "distinguishedName");
                    // Materialize every page before publishing topology. An incomplete search
                    // cannot establish that a missing trustParent denotes a tree root.
                    var entries = ReadPages(connection, request);
                    var resolved = new Dictionary<string, IDirectoryObject>(StringComparer.OrdinalIgnoreCase);
                    foreach (var entry in entries) {
                        var name = DomainFromNamingContext(ReadString(entry, "nCName"));
                        if (name != null) resolved.Add(name, entry);
                    }
                    topology = resolved;
                });
            }

            ReadOptionalMetadata(domain.Name, "trust classifications", () => {
                var request = new SearchRequest(domain.DefaultNamingContext, CommonFilters.TrustedDomains,
                    SearchScope.Subtree, "trustPartner", "trustType", "trustAttributes");
                var classifications = new Dictionary<string, TrustType>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in ReadPages(connection, request)) {
                    var target = ReadString(entry, "trustPartner");
                    if (target != null) classifications[target] = ClassifyTrust(entry, domain, target, topology);
                }
                foreach (var trust in classifications) domain.TrustTypes.Add(trust.Key, trust.Value);
            });
        }

        private static TrustType ClassifyTrust(IDirectoryObject trust, LdapDomainInfo domain, string target,
            IReadOnlyDictionary<string, IDirectoryObject> topology) {
            // AD trustType 3 denotes an MIT Kerberos realm and takes precedence over attributes.
            if (!trust.TryGetLongProperty("trustType", out var type)) return TrustType.Unknown;
            if (type == 3) return TrustType.Kerberos;
            if (type != 1 && type != 2) return TrustType.Unknown;
            if (!trust.TryGetLongProperty("trustAttributes", out var value)) return TrustType.Unknown;
            var attributes = (TrustAttributes)value;
            if (!attributes.HasFlag(TrustAttributes.WithinForest)) {
                return attributes.HasFlag(TrustAttributes.ForestTransitive) ? TrustType.Forest : TrustType.External;
            }
            return ClassifyWithinForestTrust(domain, target, topology);
        }

        private static TrustType ClassifyWithinForestTrust(LdapDomainInfo domain, string target,
            IReadOnlyDictionary<string, IDirectoryObject> topology) {
            if (!topology.TryGetValue(domain.Name, out var source) || !topology.TryGetValue(target, out var destination)) {
                return TrustType.Unknown;
            }
            if (!source.TryGetDistinguishedName(out var sourceDn) ||
                !destination.TryGetDistinguishedName(out var destinationDn)) return TrustType.Unknown;
            // Ambiguous parent values cannot establish either a parent-child link or a tree root.
            if (source.PropertyCount("trustParent") > 1 || destination.PropertyCount("trustParent") > 1) {
                return TrustType.Unknown;
            }
            var sourceParent = ReadString(source, "trustParent");
            var destinationParent = ReadString(destination, "trustParent");
            if ((source.PropertyCount("trustParent") == 1 && sourceParent == null) ||
                (destination.PropertyCount("trustParent") == 1 && destinationParent == null)) return TrustType.Unknown;
            if (string.Equals(sourceParent, destinationDn, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(destinationParent, sourceDn, StringComparison.OrdinalIgnoreCase)) {
                return TrustType.ParentChild;
            }
            if (sourceParent == null && destinationParent == null) {
                if (domain.ForestName == null) return TrustType.Unknown;
                if (string.Equals(domain.Name, domain.ForestName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(target, domain.ForestName, StringComparison.OrdinalIgnoreCase)) return TrustType.TreeRoot;
            }
            return TrustType.CrossLink;
        }

        private static string ReadPdcHostname(IConnection connection, IDirectoryObject domainRoot) {
            var owner = ReadString(domainRoot, "fSMORoleOwner");
            const string ntdsPrefix = "CN=NTDS Settings,";
            if (owner == null || !owner.StartsWith(ntdsPrefix, StringComparison.OrdinalIgnoreCase)) return null;
            // Remove only the fixed NTDS Settings RDN, preserving escaped commas in
            // the parent server DN. The hostname is data, never a connection target.
            var serverDn = owner.Substring(ntdsPrefix.Length);
            if (string.IsNullOrWhiteSpace(serverDn)) return null;
            var entries = connection.Search(new SearchRequest(serverDn, "(objectClass=server)",
                SearchScope.Base, "dNSHostName"));
            return entries.Count == 1 ? ReadHostname(entries[0]) : null;
        }

        private static List<string> ReadControllerNames(IConnection connection, string defaultNamingContext) {
            var request = new SearchRequest(defaultNamingContext, CommonFilters.DomainControllers,
                SearchScope.Subtree, "dNSHostName");
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in ReadPages(connection, request)) {
                var name = ReadHostname(entry);
                if (name != null) seen.Add(name);
            }
            return seen.ToList();
        }

        private static List<IDirectoryObject> ReadPages(IConnection connection, SearchRequest request) {
            var pageControl = new PageResultRequestControl(500);
            request.Controls.Add(pageControl);
            var results = new List<IDirectoryObject>();
            do {
                var entries = connection.SearchPage(request, out var cookie);
                // Without the response control we cannot know that all pages were read.
                if (cookie == null) throw new InvalidOperationException("Missing LDAP paging response control");
                results.AddRange(entries);
                pageControl.Cookie = cookie;
            } while (pageControl.Cookie.Length != 0);

            return results;
        }

        private void ReadOptionalMetadata(string domainName, string metadata, Action read) {
            try {
                read();
            }
            catch (Exception e) when (e is LdapException or DirectoryOperationException or InvalidOperationException or ArgumentException or FormatException) {
                _log.LogDebug(e, "Controlled domain resolution could not read additional metadata {Metadata} for domain {Domain}",
                    metadata, domainName);
            }
        }

        private static string ReadHostname(IDirectoryObject entry) {
            var name = ReadString(entry, "dNSHostName");
            return name != null && Uri.CheckHostName(name) == UriHostNameType.Dns ? name : null;
        }

        private static bool MatchesSuppliedDomain(IConnection connection, string suppliedDomain,
            string domainName, string defaultNamingContext, string configurationNamingContext) {
            // Automatic endpoint selection accepts the advertised identity. Validation applies
            // only to the domain the caller explicitly requested.
            if (suppliedDomain == null) return true;

            // Treat dotted input as a DNS name and single-label input as a NetBIOS alias.
            if (suppliedDomain.IndexOf('.') >= 0) {
                // A single terminal dot denotes the DNS root. Remove it only for identity
                // comparison, preserving the caller's endpoint and any other empty labels.
                var dnsDomain = suppliedDomain;
                if (dnsDomain.EndsWith(".", StringComparison.Ordinal)) {
                    dnsDomain = dnsDomain.Substring(0, dnsDomain.Length - 1);
                }
                return string.Equals(dnsDomain, domainName, StringComparison.OrdinalIgnoreCase);
            }

            // RootDSE does not advertise the NetBIOS alias. Read the cross-reference for this
            // specific naming context, using the same connection even with a pinned server.
            // Configuration metadata becomes required when it is needed to validate an alias.
            if (configurationNamingContext == null) return false;

            var partitionsDn = "CN=Partitions," + configurationNamingContext;
            var filter = "(&(objectClass=crossRef)(nCName=" + EscapeFilterValue(defaultNamingContext) + "))";
            var crossRefRequest = new SearchRequest(partitionsDn, filter, SearchScope.OneLevel,
                "nCName", "nETBIOSName");
            var crossRefs = connection.Search(crossRefRequest);
            if (crossRefs.Count != 1) return false;

            var crossRef = crossRefs[0];
            var advertisedNamingContext = ReadString(crossRef, "nCName");
            if (!string.Equals(advertisedNamingContext, defaultNamingContext, StringComparison.OrdinalIgnoreCase)) {
                return false;
            }

            var advertisedAlias = ReadString(crossRef, "nETBIOSName");
            return string.Equals(advertisedAlias, suppliedDomain, StringComparison.OrdinalIgnoreCase);
        }

        private static string Normalize(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        private static string ReadString(IDirectoryObject entry, string attributeName) {
            // The wrapper handles LDAP value conversion. Keep the resolver's stricter
            // single-value requirement so ambiguous naming contexts or aliases cannot match.
            if (entry.PropertyCount(attributeName) != 1) return null;
            return entry.TryGetProperty(attributeName, out var value) ? Normalize(value) : null;
        }

        private static string DomainFromNamingContext(string namingContext) {
            if (namingContext == null) return null;
            var name = Helpers.DistinguishedNameToDomain(namingContext);
            // The shared DN helper can yield an empty DNS label for a malformed DC component.
            if (name == null || name.Split('.').Any(string.IsNullOrWhiteSpace)) return null;
            return name;
        }

        private static string EscapeFilterValue(string value) {
            // A DN used as a filter value needs filter escaping, even though it came from LDAP.
            // Escape backslashes first so later replacements do not escape their own sequences.
            return value.Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        // Test seam limited to the direct resolver's operations and connection ownership.
        internal interface IConnection : IDisposable {
            void Bind();
            IReadOnlyList<IDirectoryObject> Search(SearchRequest request);
            // A null cookie means the response omitted the paging control; empty means complete.
            IReadOnlyList<IDirectoryObject> SearchPage(SearchRequest request, out byte[] cookie);
        }

        // Thin adapter over direct LDAP operations; it performs no discovery or pool access.
        private sealed class Connection : IConnection {
            private readonly LdapConnection _connection;

            internal Connection(LdapConnection connection) => _connection = connection;

            public void Bind() => _connection.Bind();

            public IReadOnlyList<IDirectoryObject> Search(SearchRequest request) {
                var response = (SearchResponse)_connection.SendRequest(request);
                return WrapEntries(response);
            }

            public IReadOnlyList<IDirectoryObject> SearchPage(SearchRequest request, out byte[] cookie) {
                var response = (SearchResponse)_connection.SendRequest(request);
                cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
                return WrapEntries(response);
            }

            private static IReadOnlyList<IDirectoryObject> WrapEntries(SearchResponse response) {
                // Reuse the common attribute accessors and expose the existing test abstraction.
                return response.Entries.Cast<SearchResultEntry>()
                    .Select(entry => (IDirectoryObject)new SearchResultEntryWrapper(entry)).ToArray();
            }

            public void Dispose() => _connection.Dispose();
        }
    }
}

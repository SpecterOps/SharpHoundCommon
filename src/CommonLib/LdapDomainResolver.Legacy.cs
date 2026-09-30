using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Models;
using TrustType = SharpHoundCommonLib.Enums.TrustType;

namespace SharpHoundCommonLib {
    internal sealed partial class LdapDomainResolver {
        // Reports fallback use so callers can avoid caching legacy results.
        internal bool TryResolveWithFallback(string domainName, out LdapDomainInfo domain, out bool usedLegacy) {
            usedLegacy = false;
            if (TryResolve(domainName, out domain)) return true;
            if (!_config.AllowUncontrolledDomainFallback) return false;

            usedLegacy = true;
            _log.LogWarning("Using uncontrolled framework domain fallback for domain {Domain}; configured LDAP settings may be ignored",
                domainName);
            return TryResolveLegacy(domainName, out domain);
        }

        private bool TryResolveLegacy(string domainName, out LdapDomainInfo domain) {
            domain = null;
            try {
                using (var legacy = _getLegacyDomain(domainName)) {
                    if (legacy == null) return false;
                    var name = Normalize(legacy.Name);
                    var namingContext = Normalize(legacy.DefaultNamingContext);
                    if (name == null || DomainFromNamingContext(namingContext) == null) return false;

                    var result = new LdapDomainInfo { Name = name, DefaultNamingContext = namingContext };
                    ReadLegacyAdditionalMetadata(legacy, result);
                    domain = result;
                }
                return true;
            }
            catch (Exception e) {
                domain = null;
                _log.LogDebug(e, "Uncontrolled domain fallback failed for domain {Domain}", domainName);
                return false;
            }
        }

        private void ReadLegacyAdditionalMetadata(ILegacyDomain legacy, LdapDomainInfo domain) {
            // Each read is independent: missing optional data must preserve the core identity.
            ReadLegacyMetadata(domain.Name, "forest name", () => domain.ForestName = Normalize(legacy.ForestName));
            ReadLegacyMetadata(domain.Name, "configuration naming context", () =>
                domain.ConfigurationNamingContext = Normalize(legacy.ReadNamingContext("configurationNamingContext")));
            ReadLegacyMetadata(domain.Name, "schema naming context", () =>
                domain.SchemaNamingContext = Normalize(legacy.ReadNamingContext("schemaNamingContext")));
            ReadLegacyMetadata(domain.Name, "domain SID", () => domain.DomainSid = Normalize(legacy.DomainSid));
            ReadLegacyMetadata(domain.Name, "PDC hostname", () => domain.PdcRoleOwnerName = Normalize(legacy.PdcRoleOwnerName));
            ReadLegacyMetadata(domain.Name, "controller hostnames", () => {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var controller in legacy.ReadControllerNames()) {
                    var hostname = Normalize(controller);
                    if (hostname != null && seen.Add(hostname)) domain.DomainControllerNames.Add(hostname);
                }
            });
            ReadLegacyMetadata(domain.Name, "trust classifications", () => {
                foreach (var trust in legacy.ReadTrustTypes()) {
                    var target = Normalize(trust.Key);
                    if (target != null) domain.TrustTypes[target] = trust.Value;
                }
            });
        }

        private void ReadLegacyMetadata(string domainName, string metadata, Action read) {
            try {
                read();
            }
            catch (Exception e) {
                _log.LogDebug(e, "Uncontrolled domain fallback could not read additional metadata {Metadata} for domain {Domain}",
                    metadata, domainName);
            }
        }

        private ILegacyDomain OpenLegacyDomain(string domainName) {
            DirectoryContext context;
            if (_config.Username != null) {
                context = domainName != null
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName, _config.Username, _config.Password)
                    : new DirectoryContext(DirectoryContextType.Domain, _config.Username, _config.Password);
            }
            else {
                context = domainName != null
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                    : new DirectoryContext(DirectoryContextType.Domain);
            }
            var domain = Domain.GetDomain(context);
            return domain == null ? null : new LegacyDomain(domain, _config);
        }

        private sealed class LegacyDomain : ILegacyDomain {
            private readonly Domain _domain;
            private readonly LdapConfig _config;

            internal LegacyDomain(Domain domain, LdapConfig config) {
                _domain = domain;
                _config = config;
            }

            public string Name => _domain.Name;

            public string DefaultNamingContext {
                get {
                    using (var entry = _domain.GetDirectoryEntry()) {
                        return entry.Properties["distinguishedName"].Value as string;
                    }
                }
            }

            public string ForestName {
                get {
                    using (var forest = _domain.Forest) {
                        return forest.Name;
                    }
                }
            }

            public string DomainSid {
                get {
                    using (var entry = _domain.GetDirectoryEntry()) {
                        var bytes = entry.Properties["objectSid"].Value as byte[];
                        return bytes == null ? null : new SecurityIdentifier(bytes, 0).Value;
                    }
                }
            }

            public string PdcRoleOwnerName {
                get {
                    using (var controller = _domain.PdcRoleOwner) {
                        return controller.Name;
                    }
                }
            }

            public string ReadNamingContext(string attribute) {
                using (var root = new DirectoryEntry("LDAP://" + _domain.Name + "/RootDSE",
                           _config.Username, _config.Username == null ? null : _config.Password)) {
                    return root.Properties[attribute].Value as string;
                }
            }

            public IReadOnlyList<string> ReadControllerNames() {
                var controllers = _domain.DomainControllers;
                var names = new List<string>();
                try {
                    foreach (DomainController controller in controllers) names.Add(controller.Name);
                }
                finally {
                    foreach (DomainController controller in controllers) controller.Dispose();
                }
                return names;
            }

            public IReadOnlyDictionary<string, TrustType> ReadTrustTypes() {
                var trusts = new Dictionary<string, TrustType>(StringComparer.OrdinalIgnoreCase);
                foreach (TrustRelationshipInformation trust in _domain.GetAllTrustRelationships()) {
                    // Match enum names explicitly; the framework and output enum values differ.
                    trusts[trust.TargetName] = Enum.TryParse(trust.TrustType.ToString(), out TrustType type)
                        ? type : TrustType.Unknown;
                }
                return trusts;
            }

            public void Dispose() => _domain.Dispose();
        }
    }
}

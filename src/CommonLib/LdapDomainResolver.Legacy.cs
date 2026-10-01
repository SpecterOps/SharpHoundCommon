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
        // Reports which resolution path supplied the identity.
        internal bool TryResolveWithFallback(string domainName, out LdapDomainInfo domain, out bool usedLegacy) {
            return TryResolveWithFallback(domainName, out domain, out usedLegacy, out _);
        }

        internal bool TryResolveWithFallback(string domainName, out LdapDomainInfo domain, out bool usedLegacy,
            out MetadataState metadata) {
            usedLegacy = false;
            var success = TryResolveMetadata(domainName, null, out metadata);
            domain = metadata?.Domain;
            if (success) return true;
            if (!_config.AllowUncontrolledDomainFallback) return false;

            usedLegacy = true;
            _log.LogWarning("Using uncontrolled framework domain fallback for domain {Domain}; configured LDAP settings may be ignored",
                domainName);
            success = TryResolveLegacy(domainName, null, out metadata);
            domain = metadata?.Domain;
            return success;
        }

        private bool TryResolveLegacy(string domainName, MetadataState previous, out MetadataState metadata) {
            metadata = null;
            try {
                using (var legacy = _getLegacyDomain(domainName)) {
                    if (legacy == null) return false;
                    var name = Normalize(legacy.Name);
                    var namingContext = Normalize(legacy.DefaultNamingContext);
                    if (name == null || DomainFromNamingContext(namingContext) == null) return false;

                    if (previous != null &&
                        (!string.Equals(previous.Domain.Name, name, StringComparison.OrdinalIgnoreCase) ||
                         !string.Equals(previous.Domain.DefaultNamingContext, namingContext,
                             StringComparison.OrdinalIgnoreCase))) return false;

                    var result = previous?.Copy() ?? new MetadataState {
                        Domain = new LdapDomainInfo { Name = name, DefaultNamingContext = namingContext },
                        UsedLegacy = true,
                        ForestRead = false,
                        ConfigurationRead = false,
                        SchemaRead = false,
                        TopologyRead = true
                    };
                    ReadLegacyAdditionalMetadata(legacy, result);
                    metadata = result;
                }
                return true;
            }
            catch (Exception e) {
                metadata = null;
                _log.LogDebug(e, "Uncontrolled domain fallback failed for domain {Domain}", domainName);
                return false;
            }
        }

        private void ReadLegacyAdditionalMetadata(ILegacyDomain legacy, MetadataState metadata) {
            var domain = metadata.Domain;
            // Each read is independent: missing optional data must preserve the core identity.
            ReadLegacyMetadata(domain.Name, "forest name", ref metadata.ForestRead, () =>
                domain.ForestName = Normalize(legacy.ForestName));
            ReadLegacyMetadata(domain.Name, "configuration naming context", ref metadata.ConfigurationRead, () =>
                domain.ConfigurationNamingContext = Normalize(legacy.ReadNamingContext("configurationNamingContext")));
            ReadLegacyMetadata(domain.Name, "schema naming context", ref metadata.SchemaRead, () =>
                domain.SchemaNamingContext = Normalize(legacy.ReadNamingContext("schemaNamingContext")));
            ReadLegacyMetadata(domain.Name, "domain SID", ref metadata.SidRead, () =>
                domain.DomainSid = Normalize(legacy.DomainSid));
            ReadLegacyMetadata(domain.Name, "PDC hostname", ref metadata.PdcRead, () =>
                domain.PdcRoleOwnerName = Normalize(legacy.PdcRoleOwnerName));
            ReadLegacyMetadata(domain.Name, "controller hostnames", ref metadata.ControllersRead, () => {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var names = new List<string>();
                foreach (var controller in legacy.ReadControllerNames()) {
                    var hostname = Normalize(controller);
                    if (hostname != null && seen.Add(hostname)) names.Add(hostname);
                }
                domain.DomainControllerNames.AddRange(names);
            });
            ReadLegacyMetadata(domain.Name, "trust classifications", ref metadata.TrustsRead, () => {
                var trusts = new Dictionary<string, TrustType>(StringComparer.OrdinalIgnoreCase);
                foreach (var trust in legacy.ReadTrustTypes()) {
                    var target = Normalize(trust.Key);
                    if (target != null) trusts[target] = trust.Value;
                }
                domain.TrustTypes.Clear();
                foreach (var trust in trusts) domain.TrustTypes.Add(trust.Key, trust.Value);
            });
        }

        private void ReadLegacyMetadata(string domainName, string metadata, ref bool completed, Action read) {
            if (completed) return;
            try {
                read();
                completed = true;
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

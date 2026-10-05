using System;
using System.Collections.Generic;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib {
    internal sealed partial class LdapDomainResolver {
        // Completion is independent of values: null, empty, and Unknown can all be successful reads.
        internal sealed class MetadataState {
            internal LdapDomainInfo Domain;
            internal string Endpoint;
            internal bool UsedLegacy;
            internal bool ForestRead = true;
            internal bool ConfigurationRead = true;
            internal bool SchemaRead = true;
            internal bool SidRead;
            internal bool PdcRead;
            internal bool ControllersRead;
            internal bool TopologyRead;
            internal bool TrustsRead;
            internal Dictionary<string, TopologyEntry> Topology = new(StringComparer.OrdinalIgnoreCase);
            internal List<TrustRecord> Trusts = new();

            internal bool Complete => ForestRead && ConfigurationRead && SchemaRead &&
                SidRead && PdcRead && ControllersRead && TopologyRead && TrustsRead;

            internal MetadataState Copy() {
                // Topology and trust records contain only plain values and are replaced as complete sets.
                // The public snapshot needs its own collections so refresh never mutates an earlier result.
                var copy = (MetadataState)MemberwiseClone();
                copy.Domain = new LdapDomainInfo {
                    Name = Domain.Name,
                    DefaultNamingContext = Domain.DefaultNamingContext,
                    ForestName = Domain.ForestName,
                    ConfigurationNamingContext = Domain.ConfigurationNamingContext,
                    SchemaNamingContext = Domain.SchemaNamingContext,
                    DomainSid = Domain.DomainSid,
                    PdcRoleOwnerName = Domain.PdcRoleOwnerName
                };
                copy.Domain.DomainControllerNames.AddRange(Domain.DomainControllerNames);
                foreach (var trust in Domain.TrustTypes) copy.Domain.TrustTypes.Add(trust.Key, trust.Value);
                return copy;
            }
        }

        internal sealed class TopologyEntry {
            internal string DistinguishedName;
            internal string Parent;
            internal bool Valid;
        }

        internal sealed class TrustRecord {
            internal string Target;
            internal long? Type;
            internal long? Attributes;
        }
    }
}

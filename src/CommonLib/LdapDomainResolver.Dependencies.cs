using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib {
    // Internal dependency contracts and injection for tests without AD access.
    // Concrete LDAP and framework adapters stay beside their resolution logic.
    internal sealed partial class LdapDomainResolver {
        // Creates an unbound connection owned and disposed by the resolver.
        internal delegate IConnection ConnectionFactory(string target, bool ssl, bool pinServer);

        // Reads the USERDNSDOMAIN endpoint hint when no explicit target or UserDomain hint is available.
        internal delegate string EnvironmentDomainReader();

        internal LdapDomainResolver(LdapConfig config,
            ConnectionFactory createConnection, EnvironmentDomainReader getEnvironmentDomain,
            ILogger log = null, Func<string, ILegacyDomain> getLegacyDomain = null) {
            _config = config;
            _createConnection = createConnection;
            _getEnvironmentDomain = getEnvironmentDomain;
            _log = log ?? Logging.LogProvider.CreateLogger("LdapDomainResolver");
            _getLegacyDomain = getLegacyDomain ?? OpenLegacyDomain;
        }

        // Limited to direct resolver operations and connection ownership.
        internal interface IConnection : IDisposable {
            void Bind();
            IReadOnlyList<IDirectoryObject> Search(SearchRequest request);
            // A null cookie means the response omitted the paging control; empty means complete.
            IReadOnlyList<IDirectoryObject> SearchPage(SearchRequest request, out byte[] cookie);
        }

        // Owned by the resolver; only plain values leave the private framework adapter.
        internal interface ILegacyDomain : IDisposable {
            string Name { get; }
            string DefaultNamingContext { get; }
            string ForestName { get; }
            string DomainSid { get; }
            string PdcRoleOwnerName { get; }
            string ReadNamingContext(string attribute);
            IReadOnlyList<string> ReadControllerNames();
            IReadOnlyDictionary<string, TrustType> ReadTrustTypes();
        }
    }
}

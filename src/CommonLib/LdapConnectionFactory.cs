using System;
using System.DirectoryServices.Protocols;
using System.Net;

namespace SharpHoundCommonLib {
    internal static class LdapConnectionFactory {
        // Creates an unbound connection. The caller owns binding, retries, and disposal.
        internal static LdapConnection Create(LdapConfig config, string target, bool ssl,
            bool globalCatalog = false, bool pinServer = false) {
            var port = globalCatalog ? config.GetGCPort(ssl) : config.GetPort(ssl);
            var identifier = new LdapDirectoryIdentifier(target, port, pinServer, false);
            var connection = new LdapConnection(identifier);
            try {
                connection.Timeout = TimeSpan.FromMinutes(5);
                connection.SessionOptions.ProtocolVersion = 3;
                // Referral chasing does not work with paged searches.
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                if (pinServer) connection.SessionOptions.AutoReconnect = false;
                if (ssl) connection.SessionOptions.SecureSocketLayer = true;

                var signing = !config.DisableSigning && !ssl;
                connection.SessionOptions.Signing = signing;
                connection.SessionOptions.Sealing = signing;

                if (config.DisableCertVerification)
                    connection.SessionOptions.VerifyServerCertificate = (_, _) => true;

                if (config.Username != null)
                    connection.Credential = new NetworkCredential(config.Username, config.Password);

                connection.AuthType = config.AuthType;
                return connection;
            }
            catch {
                connection.Dispose();
                throw;
            }
        }
    }
}

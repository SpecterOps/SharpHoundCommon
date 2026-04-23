using System.DirectoryServices.Protocols;
using System.Text;

namespace SharpHoundCommonLib
{
    public class LdapConfig
    {
        public string Username { get; set; } = null;
        public string Password { get; set; } = null;
        public string Server { get; set; } = null;
        public int Port { get; set; } = 0;
        public int SSLPort { get; set; } = 0;
        public bool ForceSSL { get; set; } = false;
        public bool DisableSigning { get; set; } = false;
        public bool DisableCertVerification { get; set; } = false;
        public bool SkipDenyAces { get; set; } = false;
        public AuthType AuthType { get; set; } = AuthType.Kerberos;
        public int MaxConcurrentQueries { get; set; } = 15;

        //Returns the port for connecting to LDAP. Will always respect a user's overridden config over anything else
        public int GetPort(bool ssl)
        {
            if (ssl && SSLPort != 0) {
                return SSLPort;
            }
            if (!ssl && Port != 0)
            {
                return Port;
            }

            return ssl ? 636 : 389;
        }
        
        public int GetGCPort(bool ssl)
        {
            return ssl ? 3269 : 3268;
        }

        public override string ToString() {
            var sb = new StringBuilder();
            sb.AppendLine($"Server: {Server}");
            sb.AppendLine($"LdapPort: {GetPort(false)}");
            sb.AppendLine($"LdapSSLPort: {GetPort(true)}");
            sb.AppendLine($"ForceSSL: {ForceSSL}");
            sb.AppendLine($"SkipDenyAces: {SkipDenyAces}");
            sb.AppendLine($"AuthType: {AuthType.ToString()}");
            sb.AppendLine($"MaxConcurrentQueries: {MaxConcurrentQueries}");
            if (!string.IsNullOrWhiteSpace(Username)) {
                sb.AppendLine($"Username: {Username}");    
            }

            if (!string.IsNullOrWhiteSpace(Password)) {
                sb.AppendLine($"Password: {new string('*', Password.Length)}");    
            }
            return sb.ToString();
        }
    }
}

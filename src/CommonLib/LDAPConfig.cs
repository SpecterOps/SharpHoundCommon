using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    public class LDAPConfig
    {
        public string Username { get; set; } = null;
        public string Password { get; set; } = null;
        public string Server { get; set; } = null;
        public int Port { get; set; } = 0;
        public bool ForceSSL { get; set; } = false;
        public bool DisableSigning { get; set; } = false;
        public bool DisableCertVerification { get; set; } = false;
        public AuthType AuthType { get; set; } = AuthType.Kerberos;

        //Returns the port for connecting to LDAP. Will always respect a user's overridden config over anything else
        public int GetPort(bool ssl)
        {
            if (Port != 0)
            {
                return Port;
            }

            return ssl ? 636 : 389;
        }
        
        public int GetGCPort(bool ssl)
        {
            return ssl ? 3269 : 3268;
        }
    }
}
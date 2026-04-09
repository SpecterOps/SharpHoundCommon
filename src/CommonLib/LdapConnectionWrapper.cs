using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    public class LdapConnectionWrapper
    {
        public LdapConnection Connection;
        public DomainInfo DomainInfo;
    }
}
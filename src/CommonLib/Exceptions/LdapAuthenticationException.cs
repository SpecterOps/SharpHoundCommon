using System;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib.Exceptions
{
    public class LdapAuthenticationException : Exception
    {
        public LdapAuthenticationException(LdapException exception) : base("Error authenticating to LDAP", exception)
        {
        }
    }
}
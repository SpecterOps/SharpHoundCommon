using System;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib.Exceptions
{
    public class LdapConnectionException : Exception
    {
        public int ErrorCode { get; }
        public LdapConnectionException(LdapException innerException) : base("Failed during ldap connection tests", innerException)
        {
            ErrorCode = innerException.ErrorCode;
        }
    }
}
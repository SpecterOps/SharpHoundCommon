using System;

namespace SharpHoundCommonLib.Ntlm;

public class LdapException : Exception
{
    public int ErrorCode { get; }
    public string ServerErrorMessage { get; }

    public LdapException(string message, int errorCode, string serverErrorMessage = null)
        : base($"{message}. LDAP error code: {errorCode}{(string.IsNullOrEmpty(serverErrorMessage) ? "" : $". Server error: {serverErrorMessage}")}")
    {
        ErrorCode = errorCode;
        ServerErrorMessage = serverErrorMessage;
    }
}

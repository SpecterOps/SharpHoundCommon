using System;

namespace SharpHoundCommonLib.Ntlm;

public class LdapNativeException : Exception {
    public int ErrorCode { get; }
    public string ServerErrorMessage { get; }

    public LdapNativeException(string message, int errorCode, string serverErrorMessage = null)
        : base(
            $"{message}. LDAP error code: {errorCode}{(string.IsNullOrEmpty(serverErrorMessage) ? "" : $". Server error: {serverErrorMessage}")}") {
        ErrorCode = errorCode;
        ServerErrorMessage = serverErrorMessage;
    }
}
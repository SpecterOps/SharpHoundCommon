namespace SharpHoundCommonLib.Enums
{
    public enum LdapErrorCodes : int
    {
        Success = 0,
        StrongAuthRequired = 8,
        SaslBindInProgress = 14,
        InvalidCredentials = 49,
        Busy = 51,
        ServerDown = 81,
        LocalError = 82,
        KerberosAuthType = 83,
    }
}
namespace SharpHoundCommonLib.Enums {
    public enum LdapOption : int {
        Ssl = 0x0A,
        ProtocolVersion = 0x11,
        ResultCode = 0x31,
        ServerError = 0x33,
        ServerCertificate = 0x81,
        Sign = 0x95,
        Encrypt = 0x96,
        Timeout = 0x5002,
    }
}
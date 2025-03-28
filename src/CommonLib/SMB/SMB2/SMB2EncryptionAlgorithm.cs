namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// SMB2 Encryption Algorithms
    /// </summary>
    public enum SMB2EncryptionAlgorithm : ushort
    {
        Aes128Ccm = 0x0001,
        Aes128Gcm = 0x0002,
        Aes256Ccm = 0x0003,
        Aes256Gcm = 0x0004
    }
}

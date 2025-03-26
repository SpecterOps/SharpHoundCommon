namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// SMB2 Hash Algorithms for Preauth Integrity
    /// <remarks>
    /// For definition, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5">MS-SMB2 2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES</see>
    /// </remarks>
    /// </summary>
    public enum SMB2HashAlgorithm : ushort
    {
        Sha512 = 0x0001
    }
}

namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// SMB2 Protocol dialects
    /// </summary>
    /// <remarks>
    /// These dialects select the type of SMB that's used (e.g. SMB 2.x or SMB3.x). For definition, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8">MS-SMB2 1.7 Versioning and Capability Negotiation</see>
    /// </remarks>
    public enum SMB2Dialect : ushort
    {
        Smb202 = 0x0202,
        Smb21 = 0x0210,
        Smb30 = 0x0300,
        Smb302 = 0x0302,
        Smb311 = 0x0311
    }

}

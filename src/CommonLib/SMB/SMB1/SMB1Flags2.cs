using System;

namespace SharpHoundCommonLib.SMB.SMB1
{
    /// <summary>
    /// Flags2 field in the SMB1 header.
    /// </summary>
    /// <remarks>
    /// Defined in the following specifications:
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f">MS-CIFS 2.2.3.1 The SMB Header</see>
    /// </para>
    /// <para>
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/3c0848a6-efe9-47c2-b57a-f7e8217150b9">MS-SMB 2.2.3.1 SMB Header Extensions</see>
    /// </para>
    /// </remarks>
    [Flags]
    public enum SMB1Flags2 : ushort
    {
        /// <summary>
        /// No flags set
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// Long file names are supported.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_LONG_NAMES in the specification.
        /// </remarks>
        LongNames = 0x0001,

        /// <summary>
        /// Extended attributes are supported.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_EAS/SMB_FLAGS2_KNOWS_EAS in the specification.
        /// </remarks>
        ExtendedAttributes = 0x0002,

        /// <summary>
        /// Security signatures are supported.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_SMB_SECURITY_SIGNATURE in the specification.
        /// </remarks>
        SecuritySignatures = 0x0004,

        /// <summary>
        /// Use compression.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_COMPRESSED in the specification.
        /// </remarks>
        Compression = 0x0008,

        /// <summary>
        /// Security signatures are required.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED in the specification.
        /// </remarks>
        SecuritySignaturesRequired = 0x0010,

        /// <summary>
        /// Long name in the request.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_IS_LONG_NAME in the specification.
        /// </remarks>
        LongNameUsed = 0x0040,

        /// <summary>
        /// Path is a reparse point.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_REPARSE_PATH in the specification.
        /// </remarks>
        ReparsePath = 0x0400,

        /// <summary>
        /// Extended security negotiation is required.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_EXTENDED_SECURITY in the specification.
        /// </remarks>
        ExtendedSecurityNeeded = 0x0800,

        /// <summary>
        /// DFS should resolve path names.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_DFS in the specification.
        /// </remarks>
        DFS = 0x1000,

        /// <summary>
        /// Read when execute allowed is OK.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_PAGING_IO/SMB_FLAGS2_READ_IF_EXECUTE in the specification.
        /// </remarks>
        PagingIO_ReadIfExecute = 0x2000,

        /// <summary>
        /// Using 32-bit NT error codes or SMBSTATUS format.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_NT_STATUS in the specification.
        /// </remarks>
        NTStatus = 0x4000,

        /// <summary>
        /// Using Unicode strings.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS2_UNICODE in the specification.
        /// </remarks>
        Unicode = 0x8000
    }
}
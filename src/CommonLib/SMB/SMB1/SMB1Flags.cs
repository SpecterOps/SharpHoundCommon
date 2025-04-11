using System;

namespace SharpHoundCommonLib.SMB.SMB1
{
    /// <summary>
    /// Flags defined in the SMB1 Header.
    /// </summary>
    /// <remarks>
    /// For more information, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f">MS-CIFS 2.2.3.1 The SMB Header</see>
    /// </remarks>
    [Flags]
    public enum SMB1Flags : byte
    {
        /// <summary>
        /// No flags set
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Client can support LOCK_AND_READ commands.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_LOCK_AND_READ_OK in the specification.
        /// </remarks>
        LockAndRead = 0x01,

        /// <summary>
        /// Client has posted a big buffer.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_BUF_AVAIL in the specification.
        /// </remarks>
        ReceiveBufferPosted = 0x02,

        /// <summary>
        /// Reserved - must not be set.
        /// </summary>
        Reserved = 0x04,

        /// <summary>
        /// Path names should be treated as case insensitive.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_CASE_INSENSITIVE in the specification.
        /// </remarks>
        CaseSensitive = 0x08,

        /// <summary>
        /// Pathnames are canonicalized.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_CANONICALIZED_PATHS in the specification.
        /// </remarks>
        CanonicalizedPaths = 0x10,

        /// <summary>
        /// Opportunistic lock on file has been granted.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_OPLOCK in the specification.
        /// </remarks>
        OpLock = 0x20,

        /// <summary>
        /// Batch opportunistic lock on file has been granted.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_OPBATCH in the specification.
        /// </remarks>
        OpLockBatch = 0x40,

        /// <summary>
        /// Message is a response, not a request.
        /// </summary>
        /// <remarks>
        /// Corresponds to SMB_FLAGS_REPLY in the specification.
        /// </remarks>
        Reply = 0x80
    }

}
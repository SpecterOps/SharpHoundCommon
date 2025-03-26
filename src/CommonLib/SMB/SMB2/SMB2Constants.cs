namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// Common constant used in the SMB2 protocol
    /// </summary>
    public static class SMB2Constants
    {
        // Protocol identifiers

        // Commands
        public const ushort NegotiateCommand = 0x0000;

        // Structure sizes
        public const ushort NegotiateRequestSize = 36;

        // Status codes
        public const uint StatusSuccess = 0x00000000;
        public const uint StatusInvalidParameter = 0xC000000D;

        // Security modes
        public const ushort SigningEnabled = 0x0001;
        public const ushort SigningRequired = 0x0002;

        // Expected response structure sizes
        public const ushort ExpectedHeaderStructureSize = 0x40;
        public const ushort ExpectedNegotiateStructureSizeA = 0x41;
        public const ushort ExpectedNegotiateStructureSizeB = 0x65;


    }
}

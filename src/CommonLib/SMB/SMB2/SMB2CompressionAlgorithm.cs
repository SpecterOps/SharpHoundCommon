namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// SMB2 Compression Algorithms
    /// </summary>
    public enum SMB2CompressionAlgorithm : ushort
    {
        None = 0x0000,
        Lznt1 = 0x0001,
        Lz77 = 0x0002,
        Lz77Huffman = 0x0003,
        PatternV1 = 0x0004,
        Lz4 = 0x0005
    }
}

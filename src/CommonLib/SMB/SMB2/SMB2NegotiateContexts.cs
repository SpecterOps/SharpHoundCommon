using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// Interface for negotiate contexts
    /// </summary>
    public interface INegotiateContext
    {
        SMB2NegotiateContextType ContextType { get; }
        byte[] ToBytes();
    }

    /// <summary>
    /// SMB2 Negotiate Context Types
    /// </summary>
    /// <remarks>
    /// For definition, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7">MS-SMB2 2.2.3.1 SMB2 NEGOTIATE_CONTEXT Request Values</see>
    /// </remarks>
    public enum SMB2NegotiateContextType : ushort
    {
        PreauthIntegrityCapabilities = 0x0001,
        EncryptionCapabilities = 0x0002,
        CompressionCapabilities = 0x0003,
        NetnameNegotiateContextId = 0x0005,
        TransportCapabilities = 0x0006,
        RdmaTransformCapabilities = 0x0007,
        SigningCapabilities = 0x0008,
        ContextTypeReserved = 0x0100
    }

    /// <summary>
    /// Preauth Integrity Capabilities negotiate context
    /// </summary>
    /// <remarks>
    /// For definition, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5">MS-SMB2 2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES</see>
    /// </remarks>
    public class SMB2PreauthIntegrityCapabilities : INegotiateContext
    {
        public SMB2NegotiateContextType ContextType => SMB2NegotiateContextType.PreauthIntegrityCapabilities;
        public List<SMB2HashAlgorithm> HashAlgorithms { get; set; }
        public byte[] Salt { get; set; }

        public SMB2PreauthIntegrityCapabilities()
        {
            HashAlgorithms = [SMB2HashAlgorithm.Sha512];

            // Generate random salt
            Salt = new byte[32];
            new Random().NextBytes(Salt);
        }

        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write((ushort)ContextType);

            // Length: 2 bytes for hash algo count + 2 bytes for salt length + 2 bytes per algorithm + salt length
            int dataLength = 2 + 2 + HashAlgorithms.Count * 2 + Salt.Length;
            writer.Write((ushort)dataLength);
            writer.Write((uint)0);  // Reserved
            writer.Write((ushort)HashAlgorithms.Count);
            writer.Write((ushort)Salt.Length);
            
            foreach (var algorithm in HashAlgorithms)
            {
                writer.Write((ushort)algorithm);
            }

            writer.Write(Salt);

            return ms.ToArray();
        }
    }

    /// <summary>
    /// Encryption Capabilities negotiate context
    /// </summary>
    /// <remarks>
    /// For definition, see:
    /// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd">MS-SMB2 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES</see>
    /// </remarks>
    public class SMB2EncryptionCapabilities : INegotiateContext
    {
        public SMB2NegotiateContextType ContextType => SMB2NegotiateContextType.EncryptionCapabilities;
        public List<SMB2EncryptionAlgorithm> Ciphers { get; set; }

        public SMB2EncryptionCapabilities()
        {
            // Win11 default order
            Ciphers =
            [
                SMB2EncryptionAlgorithm.Aes128Gcm,
                SMB2EncryptionAlgorithm.Aes128Ccm,
                SMB2EncryptionAlgorithm.Aes256Gcm,
                SMB2EncryptionAlgorithm.Aes256Ccm
            ];
        }

        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write((ushort)ContextType);

            // Length: 2 bytes for cipher count + 2 bytes per cipher
            int dataLength = 2 + Ciphers.Count * 2;
            writer.Write((ushort)dataLength);
            writer.Write((uint)0);  // Reserved

            writer.Write((ushort)Ciphers.Count);
            
            foreach (var cipher in Ciphers)
            {
                writer.Write((ushort)cipher);
            }

            return ms.ToArray();
        }
    }

    /// <summary>
    /// Compression Capabilities negotiate context
    /// </summary>
    public class SMB2CompressionCapabilities : INegotiateContext
    {
        public SMB2NegotiateContextType ContextType => SMB2NegotiateContextType.CompressionCapabilities;
        public List<SMB2CompressionAlgorithm> CompressionAlgorithms { get; set; }
        public uint Flags { get; set; } = 0x00000001;  // Chained

        public SMB2CompressionCapabilities()
        {
            CompressionAlgorithms = new List<SMB2CompressionAlgorithm>
            {
                SMB2CompressionAlgorithm.PatternV1,
                SMB2CompressionAlgorithm.Lz77,
                SMB2CompressionAlgorithm.Lz77Huffman,
                SMB2CompressionAlgorithm.Lznt1,
                SMB2CompressionAlgorithm.Lz4
            };
        }

        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write((ushort)ContextType);

            // Length: 2 (algorithm count) + 2 (reserved) + 4 (flags) + 2 bytes per algorithm
            int dataLength = 2 + 2 + 4 + CompressionAlgorithms.Count * 2;
            writer.Write((ushort)dataLength);
            writer.Write((uint)0);  // Reserved

            writer.Write((ushort)CompressionAlgorithms.Count);
            writer.Write((ushort)0);
            writer.Write(Flags);

            foreach (var algorithm in CompressionAlgorithms)
            {
                writer.Write((ushort)algorithm);
            }

            return ms.ToArray();
        }
    }

    /// <summary>
    /// Signing Capabilities negotiate context
    /// </summary>
    public class SMB2SigningCapabilities : INegotiateContext
    {
        public SMB2NegotiateContextType ContextType => SMB2NegotiateContextType.SigningCapabilities;
        public List<SMB2SigningAlgorithm> SigningAlgorithms { get; set; }

        public SMB2SigningCapabilities()
        {
            SigningAlgorithms = new List<SMB2SigningAlgorithm>
            {
                SMB2SigningAlgorithm.AesGmac,
                SMB2SigningAlgorithm.AesCmac,
                SMB2SigningAlgorithm.HmacSha256
            };
        }

        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Context header
            writer.Write((ushort)ContextType);

            // Length: 2 (algorithm count) + 2 bytes per algorithm
            int dataLength = 2 + SigningAlgorithms.Count * 2;
            writer.Write((ushort)dataLength);
            writer.Write((uint)0);  // Reserved
            writer.Write((ushort)SigningAlgorithms.Count);

            foreach (var algorithm in SigningAlgorithms)
            {
                writer.Write((ushort)algorithm);
            }

            return ms.ToArray();
        }
    }

    /// <summary>
    /// NetName Negotiate Context
    /// </summary>
    public class SMB2NetnameNegotiateContext : INegotiateContext
    {
        public SMB2NegotiateContextType ContextType => SMB2NegotiateContextType.NetnameNegotiateContextId;
        public string NetName { get; set; }

        public SMB2NetnameNegotiateContext(string netName)
        {
            NetName = netName;
        }

        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Convert NetName to UTF-16LE bytes (including null terminator)
            byte[] netNameBytes = Encoding.Unicode.GetBytes(NetName + "\0");

            writer.Write((ushort)ContextType);
            writer.Write((ushort)netNameBytes.Length);
            writer.Write((uint)0);  // Reserved
            writer.Write(netNameBytes);

            return ms.ToArray();
        }
    }

    /// <summary>
    /// RDMA Transform Capabilities negotiate context
    /// </summary>
    public class SMB2RdmaTransformCapabilities : INegotiateContext
    {
        public SMB2NegotiateContextType ContextType => SMB2NegotiateContextType.RdmaTransformCapabilities;
        public List<SMB2RdmaTransformType> TransformTypes { get; set; }

        public SMB2RdmaTransformCapabilities()
        {
            TransformTypes = new List<SMB2RdmaTransformType>
            {
                SMB2RdmaTransformType.Encryption,
                SMB2RdmaTransformType.Signing
            };
        }

        public byte[] ToBytes()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Context header
            writer.Write((ushort)ContextType);

            // Length: 2 (count) + 2 (reserved) + 4 (reserved) + 2 bytes per type
            int dataLength = 2 + 2 + 4 + TransformTypes.Count * 2;
            writer.Write((ushort)dataLength);
            writer.Write((uint)0);  // Reserved
            writer.Write((ushort)TransformTypes.Count);
            writer.Write((ushort)0); // Reserved
            writer.Write((uint)0);   // Reserved

            foreach (var type in TransformTypes)
            {
                writer.Write((ushort)type);
            }

            return ms.ToArray();
        }
    }
}

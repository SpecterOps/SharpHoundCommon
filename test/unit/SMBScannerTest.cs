using System;
using SharpHoundCommonLib.SMB;
using Xunit;
using Microsoft.Extensions.Logging;
using Moq;
using System.Threading;
using System.Linq;

namespace CommonLibTest
{
    public class SMBScannerParsingTests
    {
        private readonly Mock<ILogger> _mockLogger;
        private readonly SmbScanner _scanner;

        public SMBScannerParsingTests()
        {
            _mockLogger = new Mock<ILogger>();
            _scanner = new SmbScanner(_mockLogger.Object);
        }

        [Fact]
        public void CheckSMB2SigningRequired_ValidResponse_SigningRequired()
        {
            var (error, signingRequired) = _scanner.CheckSMB2SigningRequired(Smb2NegoResp_signing_enabledAndRequired);

            Assert.False(error);
            Assert.True(signingRequired);
        }

        [Fact]
        public void CheckSMB2SigningRequired_ValidResponse_SigningEnabledNotRequired()
        {
            var smb2NegoResp_signing_disabled = Smb2NegoResp_signing_enabledAndRequired.ToArray();
            smb2NegoResp_signing_disabled[70] = 0x1; // Change the SecurityMode to 0x1(SigningEnabled, but not required)

            var (error, signingRequired) = _scanner.CheckSMB2SigningRequired(smb2NegoResp_signing_disabled);

            Assert.False(error);
            Assert.False(signingRequired);
        }

        [Fact]
        public void CheckSMB2SigningRequired_ValidResponse_SigningDisabled()
        {
            var smb2NegoResp_signing_disabled = Smb2NegoResp_signing_enabledAndRequired.ToArray();
            smb2NegoResp_signing_disabled[70] = 0x0; // Change the SecurityMode to 0x0(Signing disabled and not required)

            var (error, signingRequired) = _scanner.CheckSMB2SigningRequired(smb2NegoResp_signing_disabled);

            Assert.False(error);
            Assert.False(signingRequired);
        }


        [Fact]
        public void CheckSMB1SigningRequired_ValidResponse_SigningRequired()
        {
            var (error, signingRequired) = _scanner.CheckSMB1SigningRequired(Smb1NegoResp_signing_enabledAndRequired);

            Assert.False(error);
            Assert.True(signingRequired);
        }

        [Fact]
        public void CheckSMB1SigningRequired_ValidResponse_SigningNotRequired()
        {
            var smb1NegoResp_signing_notRequired = Smb1NegoResp_signing_enabledAndRequired.ToArray();
            smb1NegoResp_signing_notRequired[Smb1_SecurityMode_Offset] = 0x4;

            var (error, signingRequired) = _scanner.CheckSMB1SigningRequired(smb1NegoResp_signing_notRequired);

            Assert.False(error);
            Assert.False(signingRequired);
        }

        [Fact]
        public void CheckSMB1SigningRequired_ValidResponse_SigningDisabled()
        {
            var smb1NegoResp_signing_notRequired = Smb1NegoResp_signing_enabledAndRequired.ToArray();
            smb1NegoResp_signing_notRequired[Smb1_SecurityMode_Offset] = 0x3; // Signing not enabled or required

            var (error, signingRequired) = _scanner.CheckSMB1SigningRequired(Smb1NegoResp_signing_enabledAndRequired);

            Assert.False(error);
            Assert.True(signingRequired);
        }

        [Fact]
        public void CheckSMB1SigningRequired_InvalidResponse_ReturnsError()
        {
            // Arrange: SMB1 response missing expected reply flag
            var invalidSmb1Response = new byte[] {
                0x00, 0x00, 0x00, 0x2f,
                0xff, 0x53, 0x4d, 0x42,
                0x72,
                0x00, // Missing reply flag
                0x01,
                0x00, 0x00,
                0x04,
            };

            // Act
            var (error, _) = _scanner.CheckSMB1SigningRequired(invalidSmb1Response);

            // Assert
            Assert.True(error);
        }

        [Fact]
        public void CheckResponseRequiresSigning_InvalidProtocol_ThrowsFormatException()
        {
            // Arrange: Invalid protocol identifier
            var invalidProtocolResponse = new byte[] {
                0x00, 0x00, 0x00, 0x2f,
                0xaa, 0xbb, 0xcc, 0xdd,  // Invalid protocol header
                // rest omitted...
            };

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                _scanner.CheckResponseRequiresSigning(invalidProtocolResponse, parseSMB1Response: true));
        }

        [Fact]
        public void CheckResponseRequiresSigning_NullResponse_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                _scanner.CheckResponseRequiresSigning(null, parseSMB1Response: true));
        }

        private byte[] Smb2NegoResp_signing_enabledAndRequired =
            [
                // === NetBIOS Session Service Header (4 bytes) ===
                0x0, 0x0, 0x0, 0xf8,

                // === SMB2 Header (64 bytes total) ===
                0xfe, 0x53, 0x4d, 0x42, // Protocol
                0x40, 0x0,          // Header Length (64)
                0x0, 0x0,           // Credit charge
                0x0, 0x0, 0x0, 0x0, // Status (Success)
                0x0, 0x0,           // Command (0=Negotiate)
                0x1, 0x0,           // Credits Granted(1)
                0x1, 0x0, 0x0, 0x0, // Flags (1=Response)   
                0x0, 0x0, 0x0, 0x0, // Chain offset
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Message ID
                0x0, 0x0, 0x0, 0x0, // Reserved
                0x0, 0x0, 0x0, 0x0, // Tree ID
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Signature Part 1
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,// Signature Part 2
                
                // === SMB2 Negotiate Response Structure ===
                0x41, 0x0, // Size
                0x3, 0x0,  // Security Mode (0x3 = Signing Enabled, Signing Required)
                0xff, 0x2, // Dialiect
                0x0, 0x0,  // Reserved
                0x57, 0xcd, 0x6e, 0x4d, 0x22, 0x9, 0xb5,    // ServerGuid part 1
                0x4a, 0xb5, 0xf0, 0x15, 0xf6, 0x56, 0x2c,   // ServerGuid part 2
                0xd8, 0xd4,                                 // ServerGuid part 3
                0x7, 0x0, 0x0, 0x0,     // Capabilities (DFS, Leasing, Large MTU)
                0x0, 0x0, 0x80, 0x0,    // Max Transaction Size
                0x0, 0x0, 0x80, 0x0,    // Max Read Size
                0x0, 0x0, 0x80, 0x0,    // Max Write Size
                0x70, 0xa3, 0x89, 0x4a, 0x2a, 0x9e, 0xdb, 0x1, // Current time
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, // Boot time
                0x80, 0x0, // Blob offset
                0x78, 0x0, // Blob length

                // GSS security blob
                0x00, 0x00, 0x00, 0x00, 0x60, 0x76, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x6c,
                0x30, 0x6a, 0xa0, 0x3c, 0x30, 0x3a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
                0x2, 0x1e, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x6, 0x9, 0x2a, 0x86, 0x48,
                0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x6, 0xa, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2,
                0x3, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa, 0xa3, 0x2a, 0x30, 0x28, 0xa0,
                0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e,
                0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69,
                0x67, 0x6e, 0x6f, 0x72, 0x65
            ];

        private int Smb1_SecurityMode_Offset = 39;
        private byte[] Smb1NegoResp_signing_enabledAndRequired = 
            [
                // === NetBIOS Session Service Header (4 bytes) ===
                0x0, 0x0, 0x0, 0x9f, 
            
                // === SMB1 Header (32 bytes total) ===
                0xff, 0x53, 0x4d, 0x42, // Protocol
                0x72,               // Command
                0x0, 0x0, 0x0, 0x0, // Status
                0x88,               // Flags
                0x53, 0xc8,         // Flags2
                0x0, 0x0,           // PID High
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Signature
                0x0, 0x0,      // Reserved
                0xff, 0xff,    // Tree ID
                0xff, 0xfe,    // Process ID
                0x0, 0x0,      // User ID
                0x0, 0x0,      // Multiplex ID

                // === SMB1 Negotiate Response Structure ===
                0x11,      // Word Count
                0x0, 0x0,  // Selected Index
                0xf,       // Security Mode. 0xf = User Security Mode(0x1), Password(0x2), SigningEnable(0x4), SigningRequired(0x8)
                0x32, 0x0, // Max Mpx Count
                0x1, 0x0,  // Max VCs
                0x4, 0x41, 0x0, 0x0, // Max buffer size
                0x0, 0x0, 0x1, 0x0,  // Max raw buffer
                0x2f, 0x0, 0x0, 0x0,      // Session key
                0xfc, 0xf3, 0x80, 0x80,   // Capabilities
                0xc6, 0x7, 0x8f, 0x4b, 0x2f, 0x9e, 0xdb, 0x1, // System time
                0x0, 0x0,   // Server Time
                0x0,        // Challenge Length
                0x5a, 0x0,  // Byte count
                
                // GSS security blob
                0x73, 0x61, 0x6d, 0x62, 0x61, 0x76, 0x31, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Server Guid 
                0x60, 0x48, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0xe, 0x30, 0xc, 
                0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 
                0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 
                0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 
                0x67, 0x6e, 0x6f, 0x72, 0x65
            ];
    }
}

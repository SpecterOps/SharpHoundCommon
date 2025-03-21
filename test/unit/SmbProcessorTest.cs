using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class SmbProcessorTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;

        public SmbProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }
    
        [Fact]
        public async Task SmbProcessor_Scan()
        {
            var mockSmbScanner = new Mock<SmbScanner>();
            var mockSmbScanInfo = new SmbScanInfo(It.IsAny<string>());
            mockSmbScanInfo.Info = new NTLMInfo
            {
                NativeOs = It.IsAny<string>(),
                NativeLanManager = It.IsAny<string>(),
                NbtDomainName = It.IsAny<string>(),
                NbtComputer = It.IsAny<string>(),
                DomainName = It.IsAny<string>(),
                OsBuildNumber = 11,
                OsVersion = "Windows 11",
                DnsComputerName = "primary1.testlab.local",
                DnsDomainName = It.IsAny<string>(),
                DnsTreeName = It.IsAny<string>(),
                TimeStamp = default,
                SmbSigning = false
            };

            mockSmbScanner.Setup(x => x.Scan(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>()))
                .ReturnsAsync(SharpHoundRPC.Result<SmbScanInfo>.Ok(mockSmbScanInfo));
            var mockProcessor = new SmbProcessor(It.IsAny<int>(), mockSmbScanner.Object);
            var receivedStatus = new List<CSVComputerStatus>();
            mockProcessor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await mockProcessor.Scan(It.IsAny<string>(),TimeSpan.FromMinutes(2));
        
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal(CSVComputerStatus.StatusSuccess, status.Status);
            Assert.Equal(results.Result.DnsComputerName, "primary1.testlab.local");
            Assert.Equal(results.Result.OsVersion, "Windows 11");
            Assert.Equal(results.Result.OsBuild, "11");
            Assert.Equal(results.Result.SigningEnabled, false);
        }
        
        [Fact]
        public async Task SmbProcessor_TestTimeout() {
            var mockSmbScanner = new Mock<SmbScanner>();
            
            
            mockSmbScanner.Setup(x => x.Scan(It.IsAny<string>(),It.IsAny<int>(), It.IsAny<int>())).ReturnsAsync(() => {
                Task.Delay(100).Wait();
                return NtStatus.StatusAccessDenied;
            });
            var mockProcessor = new SmbProcessor(2, mockSmbScanner.Object);
            var receivedStatus = new List<CSVComputerStatus>();
            mockProcessor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await mockProcessor.Scan("primary.testlab.local",TimeSpan.FromMilliseconds(1));

            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
        
        [Fact]
        public async Task SmbProcessor_NullScanResult() {
            var mockSmbScanner = new Mock<SmbScanner>();
            var mockSmbScanInfo = new  SmbScanInfo(It.IsAny<string>());
            mockSmbScanInfo.SmbVersion = SmbVersion.SMBv1;
        
            mockSmbScanner.Setup(x => x.Scan(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>()))
                .ReturnsAsync(SharpHoundRPC.Result<SmbScanInfo>.Ok(mockSmbScanInfo));
            var mockProcessor = new SmbProcessor(It.IsAny<int>(), mockSmbScanner.Object);
            var receivedStatus = new List<CSVComputerStatus>();
            mockProcessor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await mockProcessor.Scan(It.IsAny<string>(),TimeSpan.FromMinutes(2));
        
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Unknown error", status.Status);
        }
    }
}
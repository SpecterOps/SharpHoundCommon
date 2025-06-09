using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.SMB;
using SharpHoundRPC;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class SMBProcessorTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;

        public SMBProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }
    
        [Fact]
        public async Task SmbProcessor_TestTimeout() {
            
            var mockSmbScanner = new Mock<ISmbScanner>();
            mockSmbScanner
                .Setup(x => x.ScanHost(It.IsAny<string>(), It.IsAny<int>(), default))
                .Returns(async () => {
                    await Task.Delay(100);
                    return NtStatus.StatusAccessDenied;
                });

            var mockProcessor = new SmbProcessor(2, mockSmbScanner.Object);
            var receivedStatus = new List<CSVComputerStatus>();
            mockProcessor.ComputerStatusEvent += async status => receivedStatus.Add(status);
            var results = await mockProcessor.Scan("primary.testlab.local",TimeSpan.FromMilliseconds(1));

            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
    }
}
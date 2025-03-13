using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
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
        public async Task SmbProcessor_TestTimeout() {
            var mockSmbScanner = new Mock<SmbScanner>();
            
            
            mockSmbScanner.Setup(x => x.Scan("primary.testlab.local",445, 2)).ReturnsAsync(() => {
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
    }
}
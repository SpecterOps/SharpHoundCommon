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
    public class DCLdapProcessorTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;

        public DCLdapProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }
    
        [Fact]
        public async Task DCLdapProcessor_CheckIsNtlmSigningRequired_TestTimeout() {
            var mockProcessor = new Mock<DCLdapProcessor>(2, "primary.testlab.local", null);
            
            mockProcessor.Setup(x => x.CheckIsNtlmSigningRequired()).ReturnsAsync(() => {
                Task.Delay(100).Wait();
                return NtStatus.StatusAccessDenied;
            });

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.Scan("primary.testlab.local", TimeSpan.FromMilliseconds(1));

            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
        
        [Fact]
        public async Task DCLdapProcessor_CheckIsChannelBindingDisabled_TestTimeout() {
            var mockProcessor = new Mock<DCLdapProcessor>(2, "primary.testlab.local", null);
            mockProcessor.CallBase = true;
            
            mockProcessor.Setup(x => x.CheckIsChannelBindingDisabled()).ReturnsAsync(() => {
                Task.Delay(1000).Wait();
                return NtStatus.StatusAccessDenied;
            });
            
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.Scan("primary.testlab.local", TimeSpan.FromMilliseconds(1));

            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
        
    }
}
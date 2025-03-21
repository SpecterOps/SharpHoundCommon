using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
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
        public async Task DCLdapProcessor_Scan() {
            var mockProcessor = new Mock<DCLdapProcessor>(It.IsAny<int>(), "primary.testlab.local", null);
            
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>())).ReturnsAsync(false);

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.Scan("primary.testlab.local", TimeSpan.FromMinutes(2));

            Assert.Equal(2, receivedStatus.Count);
            var status = receivedStatus[0];
            Assert.Equal(CSVComputerStatus.StatusSuccess, status.Status);
            status = receivedStatus[1];
            Assert.Equal(CSVComputerStatus.StatusSuccess, status.Status);
            Assert.True(results.HasLdap);
            Assert.True(results.HasLdaps);
            Assert.True(results.IsSigningRequired.Result);
            Assert.False(results.IsChannelBindingDisabled.Result);
        }
        
        [Fact]
        public async Task DCLdapProcessor_Scan_Failed() {
            var mockProcessor = new Mock<DCLdapProcessor>(It.IsAny<int>(), "primary.testlab.local", null);
            
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>())).Throws(new Exception("Error"));

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.Scan("primary.testlab.local", TimeSpan.FromMinutes(2));

            Assert.Equal(2, receivedStatus.Count);
            var status = receivedStatus[0];
            Assert.Contains("CheckIsNtlmSigningRequired failed: System.Exception: Error", status.Status);
            status = receivedStatus[1];
            Assert.Contains("CheckIsNtlmSigningRequired failed: System.Exception: Error", status.Status);
            Assert.True(results.HasLdap);
            Assert.True(results.HasLdaps);
            Assert.False(results.IsSigningRequired.Result);
            Assert.False(results.IsChannelBindingDisabled.Result);
            Assert.False(results.IsSigningRequired.Collected);
            Assert.False(results.IsChannelBindingDisabled.Collected);
        }
    
        [Fact]
        public async Task DCLdapProcessor_CheckScan_Timeout() {
            var mockProcessor = new Mock<DCLdapProcessor>(2, "primary.testlab.local", null);
            
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>())).ReturnsAsync(() => {
                Task.Delay(100).Wait();
                return false;
            });

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.Scan("primary.testlab.local", TimeSpan.FromMilliseconds(1));

            Assert.Equal(2, receivedStatus.Count);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
            status = receivedStatus[1];
            Assert.Equal("Timeout", status.Status);
            Assert.Equal("Timeout",results.IsSigningRequired.FailureReason);
            Assert.Equal("Timeout",results.IsChannelBindingDisabled.FailureReason);
        }

        [Fact]
        public async Task DCLdapProcessor_CheckIsNtlmSigningRequired()
        {
            var mockProcessor = new Mock<DCLdapProcessor>(It.IsAny<int>(), "primary.testlab.local", null);
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>())).ReturnsAsync(false);
            var processor = mockProcessor.Object;
            var result = await processor.CheckIsNtlmSigningRequired();
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task DCLdapProcessor_CheckIsNtlmSigningRequired_Exception()
        {
            var mockProcessor = new Mock<DCLdapProcessor>(It.IsAny<int>(), "primary.testlab.local", null);
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>())).Throws(new Exception("Error"));
            var processor = mockProcessor.Object;
            var result = await processor.CheckIsNtlmSigningRequired();
            Assert.True(result.IsFailed);
            Assert.Contains("CheckIsNtlmSigningRequired failed: System.Exception: Error", result.Error);
        }
    }
}
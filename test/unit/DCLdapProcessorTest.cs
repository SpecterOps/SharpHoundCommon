using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
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
            var mockProcessor = new Mock<DCLdapProcessor>(2, "primary.testlab.local");
            
            mockProcessor.Setup(x => x.Authenticate(new Uri($"ldap://testlab.local:389"),new LdapAuthOptions())).ReturnsAsync(() => {
                Task.Delay(100).Wait();
                return NtStatus.StatusAccessDenied;
            });
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.CheckIsNtlmSigningRequired("primary.testlab.local", TimeSpan.FromMinutes(2));

            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
        
        [Fact]
        public async Task DCLdapProcessor_CheckIsChannelBindingDisabled_TestTimeout() {
            var mockProcessor = new Mock<DCLdapProcessor>(2, "primary.testlab.local");
            
            mockProcessor.Setup(x => x.Authenticate(new Uri($"ldap://testlab.local:389"),new LdapAuthOptions())).ReturnsAsync(() => {
                Task.Delay(100).Wait();
                return NtStatus.StatusAccessDenied;
            });
            
            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.CheckIsChannelBindingDisabled("primary.testlab.local", TimeSpan.FromMinutes(2));

            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
        
    }
}
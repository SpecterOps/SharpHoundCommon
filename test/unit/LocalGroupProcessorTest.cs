using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Wrappers;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LocalGroupProcessorTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LocalGroupProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose()
        {
        }

        [WindowsOnlyFact]
        public async Task LocalGroupProcessor_TestWorkstation()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockWorkstationSAMServer();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1001";
            var results = await processor.GetLocalGroups("win10.testlab.local", machineDomainSid, "TESTLAB.LOCAL", false)
                .ToArrayAsync();

            Assert.Equal(3, results.Length);
            var adminGroup = results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Single(adminGroup.Results);
            Assert.Equal($"{machineDomainSid}-544", adminGroup.ObjectIdentifier);
            Assert.Equal("S-1-5-21-4243161961-3815211218-2888324771-512", adminGroup.Results[0].ObjectIdentifier);
            var rdpGroup = results.First(x => x.ObjectIdentifier.EndsWith("-555"));
            Assert.Equal(2, rdpGroup.Results.Length);
            Assert.Collection(rdpGroup.Results, 
                principal =>
                {
                    Assert.Equal($"{machineDomainSid}-1003", principal.ObjectIdentifier);
                    Assert.Equal(Label.LocalGroup, principal.ObjectType);
                    
                }, principal =>
                {
                    Assert.Equal($"{machineDomainSid}-544", principal.ObjectIdentifier);
                    Assert.Equal(Label.LocalGroup, principal.ObjectType);
                });
        }

        [WindowsOnlyFact]
        public async Task LocalGroupProcessor_TestDomainController()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockDCSAMServer();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();

            Assert.Equal(2, results.Length);
            var adminGroup = results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Single(adminGroup.Results);
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", adminGroup.ObjectIdentifier);
            Assert.Equal("S-1-5-21-4243161961-3815211218-2888324771-512", adminGroup.Results[0].ObjectIdentifier);
        }

        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_NonDC()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var resultTask = TestPrivateMethod.InstanceMethod<Task<NamedPrincipal>>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "WIN10.TESTLAB.LOCAL", "S-1-5-32-123-123-500", "TESTLAB.LOCAL", 544, false, false
                });

            var result = await resultTask;

            Assert.Equal("ADMINISTRATORS@WIN10.TESTLAB.LOCAL", result.PrincipalName);
            ;
            Assert.Equal("S-1-5-32-123-123-500-544", result.ObjectId);
        }

        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_DC()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var resultTask = TestPrivateMethod.InstanceMethod<Task<NamedPrincipal>>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "PRIMARY.TESTLAB.LOCAL", "S-1-5-32-123-123-1000", "TESTLAB.LOCAL", 544, true, true
                });

            var result = await resultTask;

            Assert.Equal("IGNOREME", result.PrincipalName);
            ;
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", result.ObjectId);
        }
        
        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_NullComputerDomainSid_DC_NotBuiltIn()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var resultTask = TestPrivateMethod.InstanceMethod<Task<NamedPrincipal>>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "PRIMARY.TESTLAB.LOCAL", null, "TESTLAB.LOCAL", 544, true, false
                });

            var result = await resultTask;

            Assert.Equal(null, result);
        }
        
        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_NullComputerDomainSid_NonDC()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var resultTask = TestPrivateMethod.InstanceMethod<Task<NamedPrincipal>>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "PRIMARY.TESTLAB.LOCAL", null, "TESTLAB.LOCAL", 544, false, false
                });

            var result = await resultTask;

            Assert.Equal(null, result);
        }
        
        [Fact]
        public async Task LocalGroupProcessor_ResolveGroupName_DC_NotBuiltIn()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var proc = new LocalGroupProcessor(mockUtils.Object);

            var resultTask = TestPrivateMethod.InstanceMethod<Task<NamedPrincipal>>(proc, "ResolveGroupName",
                new object[]
                {
                    "ADMINISTRATORS", "PRIMARY.TESTLAB.LOCAL", "S-1-5-32-123-123-1000", "TESTLAB.LOCAL", 544, true, false
                });

            var result = await resultTask;

            Assert.Equal("IGNOREME", result.PrincipalName);
            
            Assert.Equal("S-1-5-32-123-123-1000-544", result.ObjectId);
        }

        [Fact]
        public async Task LocalGroupProcessor_TestTimeout() {
            var mockUtils = new Mock<MockLdapUtils>();
            var mockProcessor = new Mock<LocalGroupProcessor>(mockUtils.Object, null);
            
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(() => {
                Task.Delay(100).Wait();
                return NtStatus.StatusAccessDenied;
            });
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "testlab.local", true,TimeSpan.FromMilliseconds(1))
                .ToArrayAsync();
            Assert.Empty(results);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("Timeout", status.Status);
        }
        
        [Fact]
        public async Task LocalGroupProcessor_GetLocalGroups_GetMachineSidResultFailed() {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockFailSAMServer_GetMachineSid();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();
            Assert.Empty(results);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
        }

        [Fact]
        public async Task LocalGroupProcessor_GetLocalGroups_GetDomainsResultFailed() {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockFailSAMServer_GetDomains();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();
            Assert.Empty(results);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
        }

        [Fact]
        public async Task LocalGroupProcessor_GetLocalGroups_OpenDomainResultFailed()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockFailSAMServer_OpenDomain();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();
            Assert.Empty(results);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
        }

        [Fact]
        public async Task LocalGroupProcessor_GetLocalGroups_GetAliasesFailed()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockFailSAMServer_GetAliases();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();
            Assert.Empty(results);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
        }
        
        [Fact]
        public async Task LocalGroupProcessor_GetLocalGroups_OpenAliasFailed()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockFailSAMServer_OpenAlias();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();
            
            var failureReason = results[0];
            Assert.Contains("StatusAccessDenied", failureReason.FailureReason);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
        }
        
        [Fact]
        public async Task LocalGroupProcessor_GetLocalGroups_GetMembersFailed()
        {
            var mockProcessor = new Mock<LocalGroupProcessor>(new MockLdapUtils(), null);
            var mockSamServer = new MockFailSAMServer_GetMembers();
            mockProcessor.Setup(x => x.OpenSamServer(It.IsAny<string>())).Returns(mockSamServer);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockWorkstationMachineSid}-1000";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetLocalGroups("primary.testlab.local", machineDomainSid, "TESTLAB.LOCAL", true)
                .ToArrayAsync();
            
            var failureReason = results[0];
            Assert.Contains("StatusAccessDenied", failureReason.FailureReason);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
        }
    }
}
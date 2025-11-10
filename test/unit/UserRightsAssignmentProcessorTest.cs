using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using CommonLibTest.Facades.LSAMocks.DCMocks;
using CommonLibTest.Facades.LSAMocks.WorkstationMocks;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class UserRightsAssignmentProcessorTest
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public UserRightsAssignmentProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [WindowsOnlyFact]
        public async Task UserRightsAssignmentProcessor_TestWorkstation()
        {
            var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLdapUtils(), null);
            var mockLSAPolicy = new MockWorkstationLSAPolicy();
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(mockLSAPolicy);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1001";
            var results = await processor.GetUserRightsAssignments("win10.testlab.local", machineDomainSid, "testlab.local", false)
                    .ToArrayAsync();

            Assert.Equal(3, results.Length);

            var remoteInteractive = Assert.Single(results.Where(r => r.Privilege == LSAPrivileges.RemoteInteractiveLogon));
            Assert.Equal(3, remoteInteractive.Results.Length);
            var remoteAdmin = remoteInteractive.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal($"{machineDomainSid}-544", remoteAdmin.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, remoteAdmin.ObjectType);
            var remoteBackupOperators = remoteInteractive.Results.First(x => x.ObjectIdentifier.EndsWith("-551"));
            Assert.Equal($"{machineDomainSid}-551", remoteBackupOperators.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, remoteBackupOperators.ObjectType);
            var remoteRdp = remoteInteractive.Results.First(x => x.ObjectIdentifier.EndsWith("-555"));
            Assert.Equal($"{machineDomainSid}-555", remoteRdp.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, remoteRdp.ObjectType);

            var backup = Assert.Single(results.Where(r => r.Privilege == LSAPrivileges.Backup));
            Assert.Equal(2, backup.Results.Length);
            var backupAdmin = backup.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal($"{machineDomainSid}-544", backupAdmin.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, backupAdmin.ObjectType);
            var backupOperators = backup.Results.First(x => x.ObjectIdentifier.EndsWith("-551"));
            Assert.Equal($"{machineDomainSid}-551", backupOperators.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, backupOperators.ObjectType);

            var restore = Assert.Single(results.Where(r => r.Privilege == LSAPrivileges.Restore));
            Assert.Equal(2, restore.Results.Length);
            var restoreAdmin = restore.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal($"{machineDomainSid}-544", restoreAdmin.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, restoreAdmin.ObjectType);
            var restoreOperators = restore.Results.First(x => x.ObjectIdentifier.EndsWith("-551"));
            Assert.Equal($"{machineDomainSid}-551", restoreOperators.ObjectIdentifier);
            Assert.Equal(Label.LocalGroup, restoreOperators.ObjectType);
        }

        [WindowsOnlyFact]
        public async Task UserRightsAssignmentProcessor_TestDC()
        {
            var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLdapUtils(), null);
            var mockLSAPolicy = new MockDCLSAPolicy();
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(mockLSAPolicy);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1000";
            var results = await processor.GetUserRightsAssignments("primary.testlab.local", machineDomainSid, "testlab.local", true)
                    .ToArrayAsync();

            Assert.Equal(3, results.Length);

            var remoteInteractive = Assert.Single(results.Where(r => r.Privilege == LSAPrivileges.RemoteInteractiveLogon));
            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(remoteInteractive));
            Assert.Single(remoteInteractive.Results);
            var remoteAdmin = remoteInteractive.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", remoteAdmin.ObjectIdentifier);
            Assert.Equal(Label.Group, remoteAdmin.ObjectType);

            var backup = Assert.Single(results.Where(r => r.Privilege == LSAPrivileges.Backup));
            Assert.Equal(2, backup.Results.Length);
            var backupAdmin = backup.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", backupAdmin.ObjectIdentifier);
            Assert.Equal(Label.Group, backupAdmin.ObjectType);
            var backupOperators = backup.Results.First(x => x.ObjectIdentifier.EndsWith("-551"));
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-551", backupOperators.ObjectIdentifier);
            Assert.Equal(Label.Group, backupOperators.ObjectType);

            var restore = Assert.Single(results.Where(r => r.Privilege == LSAPrivileges.Restore));
            Assert.Equal(2, restore.Results.Length);
            var restoreAdmin = restore.Results.First(x => x.ObjectIdentifier.EndsWith("-544"));
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", restoreAdmin.ObjectIdentifier);
            Assert.Equal(Label.Group, restoreAdmin.ObjectType);
            var restoreOperators = restore.Results.First(x => x.ObjectIdentifier.EndsWith("-551"));
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-551", restoreOperators.ObjectIdentifier);
            Assert.Equal(Label.Group, restoreOperators.ObjectType);
        }

        // Obsolete by AdaptiveTimeout
        // [Fact]
        // public async Task UserRightsAssignmentProcessor_TestTimeout() {
        //     var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLdapUtils(), null);
        //     mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(()=> {
        //         Task.Delay(100).Wait();
        //         return NtStatus.StatusAccessDenied;
        //     });
        //     var processor = mockProcessor.Object;
        //     var machineDomainSid = $"{Consts.MockDomainSid}-1000";
        //     var receivedStatus = new List<CSVComputerStatus>();
        //     processor.ComputerStatusEvent += status => {
        //         receivedStatus.Add(status);
        //         return Task.CompletedTask;
        //     };
        //     var results = await processor.GetUserRightsAssignments("primary.testlab.local", machineDomainSid, "testlab.local", true, null)
        //         .ToArrayAsync();
        //     Assert.Empty(results);
        //     Assert.Single(receivedStatus);
        //     var status = receivedStatus[0];
        //     Assert.Equal("Timeout", status.Status);
        // }

        [WindowsOnlyFact]
        public async Task UserRightsAssignmentProcessor_TestGetLocalDomainInformationFail()
        {
            var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLdapUtils(), null);
            var mockLSAPolicy = new MockFailLSAPolicy_GetLocalDomainInformation();
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(()=> {
                Task.Delay(100).Wait();
                return NtStatus.StatusAccessDenied;
            });
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(mockLSAPolicy);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1001";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetUserRightsAssignments("win10.testlab.local", machineDomainSid, "testlab.local", false)
                .ToArrayAsync();

            Assert.Empty(results);
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
            Assert.Equal("LSAGetMachineSID", status.Task);
        }
        
        [WindowsOnlyFact]
        public async Task UserRightsAssignmentProcessor_TestGetResolvedPrincipalsWithPrivilegeFail()
        {
            var mockProcessor = new Mock<UserRightsAssignmentProcessor>(new MockLdapUtils(), null);
            var mockLSAPolicy = new MockFailLSAPolicy_GetResolvedPrincipalsWithPrivilege();
            mockProcessor.Setup(x => x.OpenLSAPolicy(It.IsAny<string>())).Returns(mockLSAPolicy);
            var processor = mockProcessor.Object;
            var machineDomainSid = $"{Consts.MockDomainSid}-1001";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += async status =>  {
                receivedStatus.Add(status);
            };
            var results = await processor.GetUserRightsAssignments("win10.testlab.local", machineDomainSid, "testlab.local", false)
                .ToArrayAsync();

            Assert.Equal(3, results.Length);
            foreach (var result in results)
            {
                Assert.False(result.Collected);
                Assert.Equal("LSAEnumerateAccountsWithUserRights returned StatusAccessDenied", result.FailureReason);
            }
            Assert.Single(receivedStatus);
            var status = receivedStatus[0];
            Assert.Equal("StatusAccessDenied", status.Status);
            Assert.Equal("LSAEnumerateAccountsWithUserRight", status.Task);
        }
    }
}

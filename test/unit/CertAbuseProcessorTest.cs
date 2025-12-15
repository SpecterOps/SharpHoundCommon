using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Xunit;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace CommonLibTest 
{
    public class CertAbuseProcessorTest 
    {
        private readonly Mock<ILdapUtils> _mockLdapUtils;
        private readonly Mock<IRegistryAccessor> _mockRegistryAccessor;
        private readonly CertAbuseProcessor _certAbuseProcessor;
        
        private const string DomainName = "TEST.LOCAL";
        private const string CAName = "TEST-CA";
        private const string TargetName = "target.test.local";
        private const string TargetDomainSid = "S-1-5-21-123456789-123456789-123456789";
        private const string FailureReason = "Registry Lookup Failure";
        
        private CSVComputerStatus _receivedCompStatus;
        
        public CertAbuseProcessorTest() {
            _mockLdapUtils = new Mock<ILdapUtils>();
            _mockRegistryAccessor = new Mock<IRegistryAccessor>();
            _certAbuseProcessor = new CertAbuseProcessor(_mockLdapUtils.Object, _mockRegistryAccessor.Object);
            
            _certAbuseProcessor.ComputerStatusEvent += status =>
            {
                _receivedCompStatus = status;
                return Task.CompletedTask;
            };
        }
        
        [Theory]
        [InlineData(0x00040000, true)]
        [InlineData(0x00000000, false)]
        public async Task CertAbuseProcessor_IsUserSpecifiesSanEnabled_ReturnsResult(int editFlags, bool expectedResult) {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
            const string subValue = "EditFlags";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  true, Value = editFlags });

            var results = await _certAbuseProcessor.IsUserSpecifiesSanEnabled(TargetName, CAName, TargetDomainSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Equal(expectedResult, results.Value);
            Assert.Null(results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(CertAbuseProcessor.IsUserSpecifiesSanEnabled), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_IsUserSpecifiesSanEnabled_HandlesFailedLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
            const string subValue = "EditFlags";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.IsUserSpecifiesSanEnabled(TargetName, CAName, TargetDomainSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.IsUserSpecifiesSanEnabled), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [Theory]
        [InlineData(1, true)]
        [InlineData(0, false)]
        public async Task CertAbuseProcessor_IsRoleSeparationEnabled_ReturnsResult(int roleSeparationEnabled, bool expectedResult) {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "RoleSeparationEnabled";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  true, Value = roleSeparationEnabled });

            var results = await _certAbuseProcessor.IsRoleSeparationEnabled(TargetName, CAName, TargetDomainSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Equal(expectedResult, results.Value);
            Assert.Null(results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(CertAbuseProcessor.IsRoleSeparationEnabled), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_IsRoleSeparationEnabled_HandlesFailedLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "RoleSeparationEnabled";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.IsRoleSeparationEnabled(TargetName, CAName, TargetDomainSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.IsRoleSeparationEnabled), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }

        public static IEnumerable<object[]> ProcessEAPermissionsTestData() {
            var nullOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                false,
                null
            );
            
            var daclWithNullOpaque = new RawAcl(2, 1);
            daclWithNullOpaque.InsertAce(0, nullOpaqueAce);
            
            var emptyOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                true,
                new byte[] { 0, 0, 0, 0 }
            );

            var daclWithEmptyOpaque = new RawAcl(2, 1);
            daclWithEmptyOpaque.InsertAce(0, emptyOpaqueAce);
            
            return new List<object[]>
            {
                new object[] { null }, //null dacl
                new object[] { new RawAcl(2, 0) }, //empty dacl
                new object[] { daclWithNullOpaque }, //dacl is callback false, null opaque
                new object[] { daclWithEmptyOpaque }, //dacl is callback true, empty opaque
            };
        }
        
        //TODO: mock SAM server for sid lookups instead of fetching from localhost
        [WindowsOnlyTheory]
        [MemberData(nameof(ProcessEAPermissionsTestData))]
        public async Task CertAbuseProcessor_ProcessEAPermissions_ReturnsEmpty(RawAcl dacl) {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "EnrollmentAgentRights";
            
            //setup binary security descriptor as registry value
            var descriptor = new RawSecurityDescriptor(
                ControlFlags.DiscretionaryAclPresent,
                null,
                null,
                null,
                dacl);
            
            var regValue = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(regValue, 0);

            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    "localhost",
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  true, Value = regValue });
        
            var results = await _certAbuseProcessor.ProcessEAPermissions(CAName, DomainName, "localhost", TargetDomainSid);
        
            //Validate result
            Assert.True(results.Collected);
            Assert.Empty(results.Restrictions);
            Assert.Null(results.FailureReason);
        
            //Validate CompStatus Log
            Assert.Equal("localhost", _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(CertAbuseProcessor.ProcessEAPermissions), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_ProcessEAPermissions_HandlesFailedLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "EnrollmentAgentRights";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.ProcessEAPermissions(CAName, DomainName, TargetName, TargetDomainSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.ProcessEAPermissions), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        //TODO: mock SAM server for sid lookups instead of fetching from localhost
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_ProcessRegistryEnrollmentPermissions_ReturnsEmpty_WhenNoOwnerAndNoRules() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "Security";
            
            //setup binary security descriptor as registry value
            var descriptor = new RawSecurityDescriptor(
                ControlFlags.DiscretionaryAclPresent,
                null,  //owner is null
                null,
                null,
                null);
            
            byte[] regValue = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(regValue, 0);
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    "localhost",
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  true, Value = regValue});
        
            //get access rules returns empty
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns([]);
            _mockLdapUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            
            var results = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(CAName, DomainName, "localhost", TargetDomainSid);

            //Validate result 
            Assert.True(results.Collected);
            Assert.Empty(results.Data);
            Assert.Null(results.FailureReason);
        
            //Validate CompStatus Log
            Assert.Equal("localhost", _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(CertAbuseProcessor.ProcessRegistryEnrollmentPermissions), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_ProcessRegistryEnrollmentPermissions_HandlesFailedLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "Security";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(CAName, DomainName, TargetName, TargetDomainSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.ProcessRegistryEnrollmentPermissions), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_ProcessCertTemplates_ReturnsResolvedAndUnresolvedTemplates() {
            const string validCN = "ValidCN";
            const string invalidCN = "InvalidCN";
            
            _mockLdapUtils
                .Setup(x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((string cn, string _, string _) =>
                    cn == validCN
                        ? (true, new TypedPrincipal("test guid", Label.CertTemplate))
                        : (false, null));
            
            var results = await _certAbuseProcessor.ProcessCertTemplates([validCN, invalidCN], DomainName);

            var expectedTemplate = new TypedPrincipal("test guid", Label.CertTemplate);
            Assert.Single(results.resolvedTemplates);
            Assert.Contains(expectedTemplate, results.resolvedTemplates);
            Assert.Single(results.unresolvedTemplates);
            Assert.Contains(invalidCN, results.unresolvedTemplates);
        }
        
        [WindowsOnlyTheory]
        [InlineData("S-1-5-80")]
        [InlineData("S-1-5-82")]
        [InlineData("S-1-5-90")] 
        [InlineData("S-1-5-96")]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_ReturnsFalseForFilteredSID(string sidValue) {
            var sid = new SecurityIdentifier(sidValue);
            
            //TODO: check inputs
            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                true,
                TargetDomainSid,
                new SecurityIdentifier("S-1-5-18")
            );

            Assert.Equal((false, null), results);
        }
        
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_ResolvedDomainController_ReturnsTrue() {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var sid = new SecurityIdentifier(expectedPrincipalSID);
            
            _mockLdapUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)));
            
            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                true,
                TargetDomainSid,
                new SecurityIdentifier("S-1-5-18")
            );

            Assert.Equal((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)), results);
        }
        
        //TODO finish testing GetRegistryPrincipal

        // [Fact]
        // public void CertAbuseProcessor_GetCASecurity_HappyPath()
        // {
        //     var mockProcessor = new Mock<CertAbuseProcessor>(new MockLDAPUtils(), null);
        //     
        //     var mockRegistryKey = new Mock<IRegistryKey>();
        //     mockRegistryKey.Setup(x => x.GetValue(It.IsAny<string>(), It.IsAny<string>()))
        //         .Returns(new byte[] { 0x20, 0x20 });
        //     mockProcessor.Setup(x => x.OpenRemoteRegistry(It.IsAny<string>())).Returns(mockRegistryKey.Object);
        //
        //     var processor = mockProcessor.Object;
        //     var results = processor.GetCASecurity("testlab.local", "blah");
        //     Assert.True(results.Collected);
        // }

        // [Fact]
        // public async Task CertAbuseProcessor_ProcessCAPermissions_NullSecurity_ReturnsNull()
        // {
        //     var processor = new CertAbuseProcessor(new MockLdapUtils());
        //     
        //     CSVComputerStatus capturedStatus = null;
        //
        //     processor.ComputerStatusEvent += status =>
        //     {
        //       capturedStatus = status;
        //       return Task.CompletedTask;
        //     };
        //
        //     var results = await processor.ProcessRegistryEnrollmentPermissions(null, "DUMPSTER.FIRE", null, "test");
        //
        //     Assert.Equal("Value cannot be null. (Parameter 'machineName')", results.FailureReason);
        //     Assert.False(results.Collected);
        //     Assert.Empty(results.Data);
        //     
        //     Assert.Equal(null, capturedStatus.ComputerName);
        //     Assert.Equal("test", capturedStatus.ObjectId);
        //     Assert.Equal("Value cannot be null. (Parameter 'machineName')", capturedStatus.Status);
        //     Assert.Equal(nameof(processor.ProcessRegistryEnrollmentPermissions), capturedStatus.Task);
        // }
    }
}
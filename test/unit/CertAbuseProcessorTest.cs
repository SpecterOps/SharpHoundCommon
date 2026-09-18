using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.CollectionDefinitions;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Xunit;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest 
{
    [Collection(nameof(CacheTestCollectionDefinition))]
    public class CertAbuseProcessorTest
    {
        private readonly Mock<ILdapUtils> _mockLdapUtils;
        private readonly Mock<IRegistryAccessor> _mockRegistryAccessor;
        private readonly Mock<ISAMServerAccessor> _mockSAMServerAccessor;
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
            _mockSAMServerAccessor = new Mock<ISAMServerAccessor>();
            _certAbuseProcessor = new CertAbuseProcessor(_mockLdapUtils.Object, _mockRegistryAccessor.Object, _mockSAMServerAccessor.Object);

            _certAbuseProcessor.ComputerStatusEvent += status => {
                _receivedCompStatus = status;
                return Task.CompletedTask;
            };
            
            Cache.SetCacheInstance(Cache.CreateNewCache());
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
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = true,
                    Value = editFlags
                });

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
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = false,
                    FailureReason = FailureReason
                });

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
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = true,
                    Value = roleSeparationEnabled
                });

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
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = false,
                    FailureReason = FailureReason
                });

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

        [Fact]
        public async Task CertAbuseProcessor_ProcessEAPermissions_ReturnsEmptyResult() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "EnrollmentAgentRights";

            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = true
                });

            var results = await _certAbuseProcessor.ProcessEAPermissions(CAName, DomainName, TargetName, TargetDomainSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Empty(results.Restrictions);
            Assert.Null(results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
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
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = false,
                    FailureReason = FailureReason
                });

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
        
        [SupportedOSPlatform("windows")]
        public static IEnumerable<object[]> ProcessEAPermissionsTestData() {
            return new List<object[]>
            {
                new object[] { null }, //null dacl
                new object[] { new RawAcl(2, 0) }, //empty dacl
            };
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyTheory]
        [MemberData(nameof(ProcessEAPermissionsTestData))]
        public async Task CertAbuseProcessor_ProcessEAPermissions_ReturnsEmpty(RawAcl dacl) {
            var mockSamServer = new Mock<ISAMServer>();
            
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
                    TargetName,
                    subKey,
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = true,
                    Value = regValue
                });
            
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Ok(mockSamServer.Object));
            mockSamServer.Setup(x => x.GetMachineSid(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(new SecurityIdentifier(TargetDomainSid));

            var results = await _certAbuseProcessor.ProcessEAPermissions(CAName, DomainName, TargetName, TargetDomainSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Empty(results.Restrictions);
            Assert.Null(results.FailureReason);
        }

        [Fact]
        public async Task CertAbuseProcessor_ProcessRegistryEnrollmentPermissions_ReturnsEmptyResult() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "Security";

            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = true
                });

            var results = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(CAName, DomainName, TargetName, TargetDomainSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Empty(results.Data);
            Assert.Null(results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
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
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = false,
                    FailureReason = FailureReason
                });

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

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_ProcessRegistryEnrollmentPermissions_ReturnsEmpty_WhenNoOwnerAndNoRules() {
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(null);
            var mockSamServer = new Mock<ISAMServer>();
            
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "Security";

            //setup binary security descriptor as registry value
            var descriptor = new RawSecurityDescriptor(
                ControlFlags.DiscretionaryAclPresent,
                null,
                null,
                null,
                null);

            byte[] regValue = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(regValue, 0);

            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    TargetName,
                    subKey,
                    subValue))
                .Returns(new RegistryResult
                {
                    Collected = true,
                    Value = regValue
                });

            _mockLdapUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Ok(mockSamServer.Object));
            mockSamServer.Setup(x => x.GetMachineSid(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(new SecurityIdentifier(TargetDomainSid));
            
            //get access rules returns empty
            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns([]);

            var results = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(CAName, DomainName, TargetName, TargetDomainSid);

            //Validate result 
            Assert.True(results.Collected);
            Assert.Empty(results.Data);
            Assert.Null(results.FailureReason);
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

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_ReturnsFalseForFilteredSID() {
            var sid = new SecurityIdentifier("S-1-5-3");

            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                true,
                TargetDomainSid,
                null
            );

            Assert.Equal((false, null), results);
            _mockLdapUtils.VerifyNoOtherCalls();
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_CallsResolveIDAndType_ForDomainController() {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";

            _mockLdapUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)));

            var sid = new SecurityIdentifier(expectedPrincipalSID);

            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                true,
                TargetDomainSid,
                null
            );

            Assert.Equal((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)), results);

            _mockLdapUtils.Verify(
                x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);

            _mockLdapUtils.VerifyNoOtherCalls();
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_CallsConvertLocalWellKnownPrincipal_ForNonDomainController() {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";

            _mockLdapUtils.Setup(x => x.ConvertLocalWellKnownPrincipal(It.IsAny<SecurityIdentifier>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)));

            var sid = new SecurityIdentifier(expectedPrincipalSID);

            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                false,
                TargetDomainSid,
                null
            );

            Assert.Equal((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)), results);

            _mockLdapUtils.Verify(
                x => x.ConvertLocalWellKnownPrincipal(It.IsAny<SecurityIdentifier>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
            _mockLdapUtils.VerifyNoOtherCalls();
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_ResolvesToLocalPrincipal_ForLocalSID() {
            var expectedPrincipalType = Label.ADLocalGroup;
            var expectedPrincipalSID = $"{TargetDomainSid}-123";

            _mockLdapUtils.Setup(x => x.ConvertLocalWellKnownPrincipal(It.IsAny<SecurityIdentifier>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((false, null));

            var sid = new SecurityIdentifier(expectedPrincipalSID);

            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                false,
                TargetDomainSid,
                new SecurityIdentifier(TargetDomainSid)
            );

            Assert.Equal((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)), results);

            _mockLdapUtils.Verify(
                x => x.ConvertLocalWellKnownPrincipal(It.IsAny<SecurityIdentifier>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
            _mockLdapUtils.VerifyNoOtherCalls();
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetRegistryPrincipal_ResolvesToDomainPrincipal() {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";

            _mockLdapUtils.Setup(x => x.ConvertLocalWellKnownPrincipal(It.IsAny<SecurityIdentifier>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((false, null));
            _mockLdapUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)));

            var sid = new SecurityIdentifier(expectedPrincipalSID);

            var results = await _certAbuseProcessor.GetRegistryPrincipal(
                sid,
                DomainName,
                TargetName,
                false,
                TargetDomainSid,
                null
            );

            Assert.Equal((true, new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType)), results);

            _mockLdapUtils.Verify(
                x => x.ConvertLocalWellKnownPrincipal(It.IsAny<SecurityIdentifier>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
            _mockLdapUtils.Verify(
                x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
            _mockLdapUtils.VerifyNoOtherCalls();
        }

        [Fact]
        public void CertAbuseProcessor_OpenSamServer_CallsOpenServer_Failure() {
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Fail("Connection Failed"));
            
            var result = _certAbuseProcessor.OpenSamServer(TargetName);
            
            Assert.True(result.IsFailed);
            Assert.Null(result.Value);
        }
        
        [Fact]
        public void CertAbuseProcessor_OpenSamServer_CallsOpenServer_Success() {
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Ok(new SAMServer(null, "TestServer")));
            
            var result = _certAbuseProcessor.OpenSamServer(TargetName);
            
            Assert.True(result.IsSuccess);
            Assert.IsType<SAMServer>(result.Value);
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetMachineSid_ReturnsCachedValue() {
            Cache.AddMachineSid(TargetDomainSid, TargetDomainSid);
            
            var result = await _certAbuseProcessor.GetMachineSid(TargetName, TargetDomainSid);
            
            Assert.Equal(TargetDomainSid, result.Value);
            Assert.Null(_receivedCompStatus);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_GetMachineSid_OpenSAMFailure_ReturnsNull() {
            var error = "Connection Failed";
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Fail(error));
            
            var result = await _certAbuseProcessor.GetMachineSid(TargetName, TargetDomainSid);
            
            //Validate result
            Assert.Null(result);
            
            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.OpenSamServer), _receivedCompStatus.Task);
            Assert.Equal(error, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetMachineSid_GetMachineSidFailure_ReturnsNull() {
            var mockSamServer = new Mock<ISAMServer>();
            var error = "Sid Lookup Failed";
            
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Ok(mockSamServer.Object));
            mockSamServer.Setup(x => x.GetMachineSid(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(SharpHoundRPC.Result<SecurityIdentifier>.Fail(error));
            
            var result = await _certAbuseProcessor.GetMachineSid(TargetName, TargetDomainSid);
            
            //Validate result
            Assert.Null(result);
            
            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.GetMachineSid), _receivedCompStatus.Task);
            Assert.Equal(error, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_GetMachineSid_ReturnsSid() {
            var mockSamServer = new Mock<ISAMServer>();
            
            _mockSAMServerAccessor.Setup(x => x.OpenServer(It.IsAny<string>(), It.IsAny<SAMEnums.SamAccessMasks>()))
                .Returns(SharpHoundRPC.Result<ISAMServer>.Ok(mockSamServer.Object));
            mockSamServer.Setup(x => x.GetMachineSid(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(new SecurityIdentifier(TargetDomainSid));
            
            var result = await _certAbuseProcessor.GetMachineSid(TargetName, TargetDomainSid);
            
            //Validate result
            Assert.Equal(TargetDomainSid, result.Value);
            
            //Validate CompStatus Log
            Assert.Equal(TargetName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.GetMachineSid), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(TargetDomainSid, _receivedCompStatus.ObjectId);
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_CreateEnrollmentAgentRestriction_NullOpaque_ReturnsFalse() {
            var nullOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                false,
                null
            );
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            
            var result = await _certAbuseProcessor.CreateEnrollmentAgentRestriction(nullOpaqueAce, TargetName, DomainName, false, TargetDomainSid, sid);
            
            //Validate result
            Assert.False(result.success);
            Assert.Null(result.restriction);
            _mockLdapUtils.VerifyNoOtherCalls();
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_CreateEnrollmentAgentRestriction_UnresolvedTemplate_ReturnsFalse() {
            var emptyOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                true,
                new byte[]
                {
                    1, 0, 0, 0, //sid count
                    1, 0, 0, 0, 0, 0, 0, 0, //target sid
                    0, 0, 0, 0 //template
                }
            );
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            
            _mockLdapUtils.Setup(x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((false, null));
            
            var result = await _certAbuseProcessor.CreateEnrollmentAgentRestriction(emptyOpaqueAce, TargetName, DomainName, false, TargetDomainSid, sid);
            
            //Validate result
            Assert.False(result.success);
            Assert.Null(result.restriction);
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_CreateEnrollmentAgentRestriction_NoTemplate_ReturnsAllTemplates() {
            var emptyOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                true,
                new byte[] 
                    {
                        2, 0, 0, 0, //sid count
                        1, 0, 0, 0, 0, 0, 0, 1, //target sid S-1-1
                        1, 0, 0, 0, 0, 0, 0, 3  //target sid S-1-3
                    }
            );
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            
            _mockLdapUtils.Setup(x => x.ResolveIDAndType("S-1-1", It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal("S-1-1", Label.User)));
            _mockLdapUtils.Setup(x => x.ResolveIDAndType("S-1-3", It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal("S-1-3", Label.User)));
            
            var result = await _certAbuseProcessor.CreateEnrollmentAgentRestriction(emptyOpaqueAce, nameof(Label.User), DomainName, false, TargetDomainSid, sid);
            
            //Validate result
            Assert.True(result.success);
            Assert.True(result.restriction.AllTemplates);
            Assert.Null(result.restriction.Template);
            Assert.Equal(2, result.restriction.Targets.Length);
            Assert.Contains(result.restriction.Targets, t => t.ObjectIdentifier == "S-1-1");
            Assert.Contains(result.restriction.Targets, t => t.ObjectIdentifier == "S-1-3");
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_CreateEnrollmentAgentRestriction_WithCanonicalName_ReturnsTemplate() {
            var expectedPrincipalType = Label.CertTemplate;
            var templateOID = "E4B7F0B1-27E5-4C0F-A5C9-641A67171D05";
            
            var emptyOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                true,
                new byte[]
                {
                    1, 0, 0, 0, //sid count
                    1, 0, 0, 0, 0, 0, 0, 0, //target sid
                    77, 0, 97, 0, 99, 0, 104, 0, 105, 0, 110, 0, 101, 0, 0, 0 //Computer Template
                }
            );
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            
            _mockLdapUtils.Setup(x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), LDAPProperties.CanonicalName, It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal(templateOID, expectedPrincipalType)));
            
            var result = await _certAbuseProcessor.CreateEnrollmentAgentRestriction(emptyOpaqueAce, TargetName, DomainName, false, TargetDomainSid, sid);
            
            Assert.True(result.success);
            Assert.False(result.restriction.AllTemplates);
            Assert.NotNull(result.restriction.Template);
            _mockLdapUtils.Verify(
                x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }
        
        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task CertAbuseProcessor_CreateEnrollmentAgentRestriction_WithCertTemplateOID_ReturnsTemplate() {
            var expectedPrincipalType = Label.CertTemplate;
            var templateOID = "E4B7F0B1-27E5-4C0F-A5C9-641A67171D05";
            
            var emptyOpaqueAce = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x0000,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                true,
                new byte[]
                {
                    1, 0, 0, 0, //sid count
                    1, 0, 0, 0, 0, 0, 0, 0, //target sid
                    77, 0, 97, 0, 99, 0, 104, 0, 105, 0, 110, 0, 101, 0, 0, 0 //Computer Template
                }
            );
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            
            _mockLdapUtils.Setup(x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), LDAPProperties.CanonicalName, It.IsAny<string>()))
                .ReturnsAsync((false, null));
            _mockLdapUtils.Setup(x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), LDAPProperties.CertTemplateOID, It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal(templateOID, expectedPrincipalType)));
            
            var result = await _certAbuseProcessor.CreateEnrollmentAgentRestriction(emptyOpaqueAce, TargetName, DomainName, false, TargetDomainSid, sid);
            
            //Validate result
            Assert.True(result.success);
            Assert.False(result.restriction.AllTemplates);
            Assert.NotNull(result.restriction.Template);
            _mockLdapUtils.Verify(
                x => x.ResolveCertTemplateByProperty(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Exactly(2));
        }
    }
}
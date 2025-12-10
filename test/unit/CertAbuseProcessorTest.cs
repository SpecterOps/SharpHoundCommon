using System.Security.Principal;
using System.Threading.Tasks;
using CommonLibTest.Facades;
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
        private readonly Mock<IRegistryAccessor> _mockRegistryAccessor;
        private readonly CertAbuseProcessor _certAbuseProcessor;
        
        private const string Target = "target.test.local";
        private const string CAName = "TEST-CA";
        private const string DomainName = "TEST.LOCAL";
        private const string HostSid = "S-1-5-21-TEST-ENTERPRISE-CA";
        private const string FailureReason = "Registry Lookup Failure";
        
        private CSVComputerStatus _receivedCompStatus;
        
        public CertAbuseProcessorTest() {
            _mockRegistryAccessor = new Mock<IRegistryAccessor>();
            _certAbuseProcessor = new CertAbuseProcessor(new MockLdapUtils(), _mockRegistryAccessor.Object);
            
            _certAbuseProcessor.ComputerStatusEvent += status =>
            {
                _receivedCompStatus = status;
                return Task.CompletedTask;
            };
        }
        
        [Theory]
        [InlineData(0x00040000, true)]
        [InlineData(0x00020000, false)]
        public async Task CertAbuseProcessor_IsUserSpecifiesSanEnabled_ChecksKey(int editFlags, bool expectedResult) {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
            const string subValue = "EditFlags";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    Target,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  true, Value = editFlags });

            var results = await _certAbuseProcessor.IsUserSpecifiesSanEnabled(Target, CAName, HostSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Equal(expectedResult, results.Value);
            Assert.Null(results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(CAName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(CertAbuseProcessor.IsUserSpecifiesSanEnabled), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_IsUserSpecifiesSanEnabled_FailsLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
            const string subValue = "EditFlags";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    Target,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.IsUserSpecifiesSanEnabled(Target, CAName, HostSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(CAName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.IsUserSpecifiesSanEnabled), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        }
        
        [Theory]
        [InlineData(1, true)]
        [InlineData(0, false)]
        public async Task CertAbuseProcessor_RoleSeparationEnabled_ChecksKey(int regValue, bool expectedResult) {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "RoleSeparationEnabled";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    Target,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  true, Value = regValue });

            var results = await _certAbuseProcessor.RoleSeparationEnabled(Target, CAName, HostSid);

            //Validate result
            Assert.True(results.Collected);
            Assert.Equal(expectedResult, results.Value);
            Assert.Null(results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(CAName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(CertAbuseProcessor.RoleSeparationEnabled), _receivedCompStatus.Task);
            Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
            Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_RoleSeparationEnabled_FailsLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "RoleSeparationEnabled";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    Target,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.RoleSeparationEnabled(Target, CAName, HostSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(CAName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.RoleSeparationEnabled), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        }
        
        //TODO: test happy path
        // [Fact]
        // public async Task CertAbuseProcessor_ProcessEAPermissions_ChecksKey() {
        //     const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
        //     const string subValue = "EnrollmentAgentRights";
        //     
        //     _mockRegistryAccessor
        //         .Setup(ra => ra.GetRegistryKeyData(
        //             Target,
        //             subKey,
        //             subValue,
        //             It.IsAny<ILogger>()))
        //         .Returns(new RegistryResult { Collected =  true, Value = "regValue" });
        //
        //     var results = await _certAbuseProcessor.ProcessEAPermissions(CAName, DomainName, Target, HostSid);
        //
        //     //Validate result
        //     Assert.True(results.Collected);
        //     Assert.Equal(new EnrollmentAgentRestriction[0], results.Restrictions);
        //     Assert.Null(results.FailureReason);
        //
        //     //Validate CompStatus Log
        //     Assert.Equal(CAName, _receivedCompStatus.ComputerName);
        //     Assert.Equal(nameof(CertAbuseProcessor.ProcessEAPermissions), _receivedCompStatus.Task);
        //     Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
        //     Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        // }
        
        [Fact]
        public async Task CertAbuseProcessor_ProcessEAPermissions_FailsLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "EnrollmentAgentRights";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    Target,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.ProcessEAPermissions(CAName, DomainName, Target, HostSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(CAName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.ProcessEAPermissions), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        }
        
        //TODO: test happy path
        // [Fact]
        // public async Task CertAbuseProcessor_ProcessRegistryEnrollmentPermissions_ChecksKey() {
        //     const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
        //     const string subValue = "Security";
        //     
        //     _mockRegistryAccessor
        //         .Setup(ra => ra.GetRegistryKeyData(
        //             Target,
        //             subKey,
        //             subValue,
        //             It.IsAny<ILogger>()))
        //         .Returns(new RegistryResult { Collected =  true, Value = "regValue" });
        //
        //     var results = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(CAName, DomainName, Target, HostSid);
        //
        //     //Validate result
        //     Assert.True(results.Collected);
        //     Assert.Equal(new ACE[0], results.Data);
        //     Assert.Null(results.FailureReason);
        //
        //     //Validate CompStatus Log
        //     Assert.Equal(CAName, _receivedCompStatus.ComputerName);
        //     Assert.Equal(nameof(CertAbuseProcessor.ProcessRegistryEnrollmentPermissions), _receivedCompStatus.Task);
        //     Assert.Equal(CSVComputerStatus.StatusSuccess, _receivedCompStatus.Status);
        //     Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        // }
        
        [Fact]
        public async Task CertAbuseProcessor_ProcessRegistryEnrollmentPermissions_FailsLookup() {
            const string subKey = $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{CAName}";
            const string subValue = "Security";
            
            _mockRegistryAccessor
                .Setup(ra => ra.GetRegistryKeyData(
                    Target,
                    subKey,
                    subValue,
                    It.IsAny<ILogger>()))
                .Returns(new RegistryResult { Collected =  false, FailureReason = FailureReason });

            var results = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(CAName, DomainName, Target, HostSid);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(FailureReason, results.FailureReason);

            //Validate CompStatus Log
            Assert.Equal(CAName, _receivedCompStatus.ComputerName);
            Assert.Equal(nameof(_certAbuseProcessor.ProcessRegistryEnrollmentPermissions), _receivedCompStatus.Task);
            Assert.Equal(FailureReason, _receivedCompStatus.Status);
            Assert.Equal(HostSid, _receivedCompStatus.ObjectId);
        }
        
        [Fact]
        public async Task CertAbuseProcessor_ProcessCertTemplates_ReturnResolvedAndUnresolvedTemplates() {
            const string validCN = "ValidCN";
            const string invalidCN = "InvalidCN";
            
            var results = await _certAbuseProcessor.ProcessCertTemplates([validCN, invalidCN], DomainName);

            var expectedTemplate = new TypedPrincipal("guid", Label.CertTemplate);
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
            
            var results = await _certAbuseProcessor.GetRegistryPrincipal(sid, DomainName, Target, true,  "compId", sid);

            Assert.Equal((false, null), results);
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
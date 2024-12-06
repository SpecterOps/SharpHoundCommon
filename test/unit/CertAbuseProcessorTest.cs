using System;
using System.DirectoryServices;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    //TODO: Make these tests work
    public class CertAbuseProcessorTest : IDisposable {
        private const string CASecurityFixture =
            "AQAUhCABAAAwAQAAFAAAAEQAAAACADAAAgAAAALAFAD//wAAAQEAAAAAAAEAAAAAAsAUAP//AAABAQAAAAAABQcAAAACANwABwAAAAADGAABAAAAAQIAAAAAAAUgAAAAIAIAAAADGAACAAAAAQIAAAAAAAUgAAAAIAIAAAADJAABAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAADJAACAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAADJAABAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQBwIAAAADJAACAAAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQBwIAAAADFAAAAgAAAQEAAAAAAAULAAAAAQIAAAAAAAUgAAAAIAIAAAECAAAAAAAFIAAAACACAAA=";

        private readonly ITestOutputHelper _testOutputHelper;

        public CertAbuseProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }

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
        // public void CertAbuseProcessor_GetTrustedCerts_EmptyForNonRoot()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(false);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetTrustedCerts("testlab.local");
        //     Assert.Empty(results);
        // }
        //
        // [Fact]
        // public void CertAbuseProcessor_GetTrustedCerts_NullConfigPath_ReturnsEmpty()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(true);
        //     mockUtils.Setup(x => x.GetConfigurationPath(It.IsAny<string>())).Returns((string)null);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetTrustedCerts("testlab.local");
        //     Assert.Empty(results);
        // }
        //
        // [Fact]
        // public void CertAbuseProcessor_GetRootCAs_EmptyForNonRoot()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(false);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetRootCAs("testlab.local");
        //     Assert.Empty(results);
        // }
        //
        // [Fact]
        // public void CertAbuseProcessor_GetRootCAs_NullConfigPath_ReturnsEmpty()
        // {
        //     var mockUtils = new Mock<MockLDAPUtils>();
        //     mockUtils.Setup(x => x.IsForestRoot(It.IsAny<string>())).Returns(true);
        //     mockUtils.Setup(x => x.GetConfigurationPath(It.IsAny<string>())).Returns((string)null);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //
        //     var results = processor.GetRootCAs("testlab.local");
        //     Assert.Empty(results);
        // }

        [Fact]
        public async Task CertAbuseProcessor_ProcessCAPermissions_NullSecurity_ReturnsNull()
        {
            var processor = new CertAbuseProcessor(new MockLdapUtils());

            var results = await processor.ProcessRegistryEnrollmentPermissions(null, "DUMPSTER.FIRE", null, "test");

            Assert.Equal("Value cannot be null. (Parameter 'machineName')", results.FailureReason);
            Assert.False(results.Collected);
            Assert.Empty(results.Data);
        }

        // [WindowsOnlyFact]
        // public void CertAbuseProcessor_ProcessCAPermissions_ReturnsCorrectValues()
        // {
        //     var mockUtils = new Mock<MockLdapUtils>();
        //     var sd = new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        //     mockUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(sd);
        //     var processor = new CertAbuseProcessor(mockUtils.Object);
        //     var bytes = Helpers.B64ToBytes(CASecurityFixture);
        //
        //     var results = processor.ProcessCAPermissions(bytes, "TESTLAB.LOCAL", "test", false);
        //     _testOutputHelper.WriteLine(JsonConvert.SerializeObject(results, Formatting.Indented));
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.Owns && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-32-544" &&
        //              x.PrincipalType == Label.Group && !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.Enroll && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-11" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCA && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-32-544" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCertificates && x.PrincipalSID == "TESTLAB.LOCAL-S-1-5-32-544" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCA &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-512" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCertificates &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-512" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCA &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-519" &&
        //              !x.IsInherited);
        //     Assert.Contains(results,
        //         x => x.RightName == EdgeNames.ManageCertificates &&
        //              x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-519" &&
        //              !x.IsInherited);
        // }
    }
}
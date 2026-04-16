using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Reflection;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    public class LDAPUtilsTest : IDisposable {
        private readonly string _testDomainName;
        private readonly string _testForestName;
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly ILdapUtils _utils;

        #region Constructor(s)

        public LDAPUtilsTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
            _testForestName = "PARENT.LOCAL";
            _testDomainName = "TESTLAB.LOCAL";
            _utils = new LdapUtils();
            // This runs once per test.
        }

        #endregion

        #region IDispose Implementation

        public void Dispose() {
            // Tear down (called once per test)
        }

        #endregion

        [Fact]
        public void SanityCheck() {
            Assert.True(true);
        }

        /// <summary>
        /// </summary>
        [Fact]
        public async Task GetUserGlobalCatalogMatches_Garbage_ReturnsNull() {
            var test = await _utils.GetGlobalCatalogMatches("foo", "bar");
            _testOutputHelper.WriteLine(test.ToString());
            Assert.True(test.Success);
            Assert.Empty(test.Sids);
        }

        [Fact]
        public async Task ResolveIDAndType_DuplicateSid_ReturnsNull() {
            var test = await _utils.ResolveIDAndType("ABC0ACNF", null);
            Assert.False(test.Success);
        }

        [Fact]
        public async void ResolveIDAndType_WellKnownAdministrators_ReturnsConvertedSID() {
            var test = await _utils.ResolveIDAndType("S-1-5-32-544", "TESTLAB.LOCAL");
            Assert.True(test.Success);
            Assert.NotNull(test.Principal);
            Assert.Equal(Label.Group, test.Principal.ObjectType);
            Assert.Equal("TESTLAB.LOCAL-S-1-5-32-544", test.Principal.ObjectIdentifier);
        }

        [Fact]
        public async void GetWellKnownPrincipal_EnterpriseDomainControllers_ReturnsCorrectedSID()
        {
            var mock = new Mock<LdapUtils>();
            mock.Setup(x => x.GetForest(It.IsAny<string>())).ReturnsAsync((true, _testForestName));
            var result = await mock.Object.GetWellKnownPrincipal("S-1-5-9", null);
            Assert.True(result.Success);
            Assert.Equal($"{_testForestName}-S-1-5-9", result.WellKnownPrincipal.ObjectIdentifier);
            Assert.Equal(Label.Group, result.WellKnownPrincipal.ObjectType);
        }

        [Fact]
        public async void GetWellKnownPrincipal_NonWellKnown_ReturnsNull() {
            var result = await _utils.GetWellKnownPrincipal("S-1-5-21-123456-78910", _testDomainName);
            Assert.False(result.Success);
            Assert.Null(result.WellKnownPrincipal);
        }

        [Fact]
        public async void GetWellKnownPrincipal_WithDomain_ConvertsSID() {
            var result =
                await _utils.GetWellKnownPrincipal("S-1-5-32-544", _testDomainName);
            Assert.True(result.Success);
            Assert.Equal(Label.Group, result.WellKnownPrincipal.ObjectType);
            Assert.Equal($"{_testDomainName}-S-1-5-32-544", result.WellKnownPrincipal.ObjectIdentifier);
        }

        [Fact]
        public async Task Test_ResolveSearchResult_BadObjectID() {
            var utils = new MockLdapUtils();
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "person" } },
                { LDAPProperties.SAMAccountType, "805306368" }
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "", "");
            var (success, _) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.False(success);
        }

        [Fact]
        public async Task Test_ResolveSearchResult_DeletedObject() {
            var utils = new MockLdapUtils();
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.IsDeleted, "true" },
            };

            var guid = new Guid().ToString();

            var mock = new MockDirectoryObject("abc", attribs,
                "", guid);
            var (success, resolved) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(guid, resolved.ObjectId);
            Assert.True(resolved.Deleted);
        }

        [Fact]
        public async Task Test_ResolveSearchResult_DCObject() {
            var utils = new MockLdapUtils();
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.SAMAccountType, "805306369" }, {
                    LDAPProperties.UserAccountControl,
                    ((int)(UacFlags.ServerTrustAccount | UacFlags.WorkstationTrustAccount)).ToString()
                },
                { LDAPProperties.DNSHostName, "primary.testlab.local" }
            };
            var guid = new Guid().ToString();
            const string sid = "S-1-5-21-3130019616-2776909439-2417379446-1001";
            const string dn = "CN=PRIMARY,OU=DOMAIN CONTROLLERS,DC=TESTLAB,DC=LOCAL";

            var mock = new MockDirectoryObject(dn, attribs, sid, guid);

            var (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.Computer, result.ObjectType);
            Assert.True(result.IsDomainController);
            Assert.Equal("PRIMARY.TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);

            mock.DistinguishedName = "";

            (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.Computer, result.ObjectType);
            Assert.True(result.IsDomainController);
            Assert.Equal("PRIMARY.TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);

            mock.Properties.Remove(LDAPProperties.DNSHostName);
            mock.Properties[LDAPProperties.CanonicalName] = "PRIMARY";
            (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.Computer, result.ObjectType);
            Assert.True(result.IsDomainController);
            Assert.Equal("PRIMARY.TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);

            mock.Properties.Remove(LDAPProperties.CanonicalName);
            mock.Properties[LDAPProperties.Name] = "PRIMARY";
            (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.Computer, result.ObjectType);
            Assert.True(result.IsDomainController);
            Assert.Equal("PRIMARY.TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);

            mock.Properties.Remove(LDAPProperties.Name);
            (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.Computer, result.ObjectType);
            Assert.True(result.IsDomainController);
            Assert.Equal("UNKNOWN.TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);
        }

        [Fact]
        public async Task Test_ResolveSearchResult_MSAGMSA() {
            var utils = new MockLdapUtils();
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.MSAClass } },
                { LDAPProperties.SAMAccountType, "805306369" },
                { LDAPProperties.SAMAccountName, "TESTMSA$" }
            };

            const string sid = "S-1-5-21-3130019616-2776909439-2417379446-2105";
            const string dn = "CN=TESTMSA,CN=MANAGED SERVICE ACCOUNTS,DC=TESTLAB,DC=LOCAL";
            var guid = new Guid().ToString();

            var mock = new MockDirectoryObject(dn, attribs, sid, guid);

            var (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.User, result.ObjectType);
            Assert.Equal("TESTMSA$@TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);
        }

        [Fact]
        public async Task Test_ResolveSearchResult_TrustAccount() {
            var utils = new MockLdapUtils();
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top"} },
                { LDAPProperties.SAMAccountType, "805306370" },
                { LDAPProperties.SAMAccountName, "DOMAIN1$" }
            };

            const string sid = "S-1-5-21-3130019616-2776909439-2417379446-2105";
            const string dn = "CN=DOMAIN1$,CN=USERS,DC=TESTLAB,DC=LOCAL";
            var guid = new Guid().ToString();

            var mock = new MockDirectoryObject(dn, attribs, sid, guid);

            var (success, result) = await LdapUtils.ResolveSearchResult(mock, utils);
            Assert.True(success);
            Assert.Equal(sid, result.ObjectId);
            Assert.Equal(Label.User, result.ObjectType);
            Assert.Equal("DOMAIN1$@TESTLAB.LOCAL", result.DisplayName);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.DomainSid);
            Assert.Equal("TESTLAB.LOCAL", result.Domain);
            Assert.False(result.Deleted);
        }

        #region CreateDirectoryEntry Tests

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Invokes the static CreateDirectoryEntry method via reflection.
        /// DirectoryEntry does not connect to the server until properties are accessed,
        /// so the call succeeds even with a fake path.
        /// </summary>
        private static IDirectoryObject InvokeCreateDirectoryEntry(LdapUtils utils, string path) {
            // Extract the LdapConfig from the LdapUtils instance via reflection.
            var configField = typeof(LdapUtils).GetField("_ldapConfig",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(configField);
            var config = (LdapConfig)configField.GetValue(utils);

            return TestPrivateMethod.StaticMethod<IDirectoryObject>(typeof(LdapUtils),
                "CreateDirectoryEntry", new object[] { path, config });
        }

        /// <summary>
        /// Extracts the underlying DirectoryEntry from its DirectoryEntryWrapper so that
        /// Path and AuthenticationType can be inspected without triggering a network call.
        /// </summary>
        private static DirectoryEntry ExtractDirectoryEntry(IDirectoryObject directoryObject) {
            var entryField = directoryObject.GetType()
                .GetField("_entry", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(entryField);
            return (DirectoryEntry)entryField.GetValue(directoryObject);
        }

        // ---------------------------------------------------------------------------
        // Path construction – no server configured
        // ---------------------------------------------------------------------------

        [Fact]
        public void CreateDirectoryEntry_NoServer_PathIsUnchanged() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig());

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://domain.com", entry.Path);
        }

        // ---------------------------------------------------------------------------
        // Path construction – server configured
        // ---------------------------------------------------------------------------

        [Fact]
        public void CreateDirectoryEntry_ServerSet_DefaultPort_InjectsServerWithoutPort() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/DC=domain,DC=com", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_CustomPort_InjectsServerWithPort() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com", Port = 3636 });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com:3636/DC=domain,DC=com", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_ForceSSL_DefaultSSLPort_InjectsServerWithoutPort() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com", ForceSSL = true });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/DC=domain,DC=com", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_ForceSSL_CustomSSLPort_InjectsServerWithPort() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com", ForceSSL = true, SSLPort = 1636 });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com:1636/DC=domain,DC=com", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_SIDPath_InjectsServerBeforeSIDMoniiker() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://<SID=S-1-5-21-123>");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/<SID=S-1-5-21-123>", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_RootDSEPath_InjectsServerBeforeSuffix() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com/RootDSE");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/RootDSE", entry.Path);
        }

        // ---------------------------------------------------------------------------
        // Path construction – domain-shortcut edge cases
        // ---------------------------------------------------------------------------

        [Fact]
        public void CreateDirectoryEntry_ServerSet_SingleLabelDomain_ConvertedToSingleDCPart() {
            // A domain name with no dots (e.g. a NetBIOS-style name) should become "DC=<name>".
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://corp");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/DC=corp", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_ExistingDNPath_ServerInjectedWithoutConversion() {
            // When the path already carries a proper DN (contains '=') it must be forwarded
            // verbatim after the server – no DC= conversion should be applied.
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://DC=domain,DC=com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/DC=domain,DC=com", entry.Path);
        }

        // ---------------------------------------------------------------------------
        // Path construction – double injection guard
        // ---------------------------------------------------------------------------

        [Fact]
        public void CreateDirectoryEntry_ServerSet_PathAlreadyHasServer_NotInjectedAgain() {
            // If the path already begins with LDAP://<server>/ the server must not be
            // prepended a second time.
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://dc01.corp.com/DC=domain,DC=com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/DC=domain,DC=com", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_CustomPort_PathAlreadyHasServerWithPort_NotInjectedAgain() {
            // Same guard when the path already carries the server with a non-default port.
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com", Port = 3636 });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://dc01.corp.com:3636/DC=domain,DC=com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com:3636/DC=domain,DC=com", entry.Path);
        }

        [Fact]
        public void CreateDirectoryEntry_ServerSet_PathAlreadyHasServerWithRootDSE_NotInjectedAgain() {
            // The guard must fire even when the path component after the server is not a DN
            // (e.g. the special "RootDSE" target used by GetNamingContextPath).
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Server = "dc01.corp.com" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://dc01.corp.com/RootDSE");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("LDAP://dc01.corp.com/RootDSE", entry.Path);
        }

        // ---------------------------------------------------------------------------
        // AuthenticationTypes – matching connection pool logic
        // ---------------------------------------------------------------------------

        [Fact]
        public void CreateDirectoryEntry_Default_HasSecureSigningAndSealing() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig()); // ForceSSL=false, DisableSigning=false

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            var expected = AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing;
            Assert.Equal(expected, entry.AuthenticationType);
        }

        [Fact]
        public void CreateDirectoryEntry_ForceSSL_HasSecureSSLOnly_NoSigningOrSealing() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { ForceSSL = true });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            var expected = AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer;
            Assert.Equal(expected, entry.AuthenticationType);
            Assert.Equal(AuthenticationTypes.None, entry.AuthenticationType & AuthenticationTypes.Signing);
            Assert.Equal(AuthenticationTypes.None, entry.AuthenticationType & AuthenticationTypes.Sealing);
        }

        [Fact]
        public void CreateDirectoryEntry_DisableSigning_HasSecureOnly() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { DisableSigning = true });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal(AuthenticationTypes.Secure, entry.AuthenticationType);
        }

        [Fact]
        public void CreateDirectoryEntry_ForceSSLAndDisableSigning_HasSecureSSLOnly() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { ForceSSL = true, DisableSigning = true });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            var expected = AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer;
            Assert.Equal(expected, entry.AuthenticationType);
        }

        // ---------------------------------------------------------------------------
        // Credentials
        // ---------------------------------------------------------------------------

        [Fact]
        public void CreateDirectoryEntry_WithCredentials_UsernameAndPasswordApplied() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { Username = "testuser", Password = "testpass" });

            var result = InvokeCreateDirectoryEntry(utils, "LDAP://domain.com");
            var entry = ExtractDirectoryEntry(result);

            Assert.Equal("testuser", entry.Username);
            Assert.Equal("LDAP://domain.com", entry.Path);
            Assert.Equal(AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing, entry.AuthenticationType);
        }

        #endregion

        #region BuildPrincipalContextParameters Tests

        // ---------------------------------------------------------------------------
        // contextName – no server configured
        // ---------------------------------------------------------------------------

        [Fact]
        public void BuildPrincipalContextParameters_NoServer_NoDomain_ContextNameIsNull() {
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(new LdapConfig());
            Assert.Null(contextName);
        }

        [Fact]
        public void BuildPrincipalContextParameters_NoServer_DomainProvided_ContextNameIsDomain() {
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(new LdapConfig(), "testlab.local");
            Assert.Equal("testlab.local", contextName);
        }

        // ---------------------------------------------------------------------------
        // contextName – server configured
        // ---------------------------------------------------------------------------

        [Fact]
        public void BuildPrincipalContextParameters_ServerSet_DefaultPort_ContextNameIsServerOnly() {
            var config = new LdapConfig { Server = "dc01.corp.com" };
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(config);
            Assert.Equal("dc01.corp.com", contextName);
        }

        [Fact]
        public void BuildPrincipalContextParameters_ServerSet_CustomPort_ContextNameIncludesPort() {
            var config = new LdapConfig { Server = "dc01.corp.com", Port = 3636 };
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(config);
            Assert.Equal("dc01.corp.com:3636", contextName);
        }

        [Fact]
        public void BuildPrincipalContextParameters_ServerSet_DomainIgnoredWhenServerPresent() {
            // The domain name should be ignored when a server is explicitly configured.
            var config = new LdapConfig { Server = "dc01.corp.com" };
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(config, "testlab.local");
            Assert.Equal("dc01.corp.com", contextName);
        }

        [Fact]
        public void BuildPrincipalContextParameters_ServerSet_ForceSSL_DefaultSSLPort_ContextNameIsServerOnly() {
            var config = new LdapConfig { Server = "dc01.corp.com", ForceSSL = true };
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(config);
            Assert.Equal("dc01.corp.com", contextName);
        }

        [Fact]
        public void BuildPrincipalContextParameters_ServerSet_ForceSSL_CustomSSLPort_ContextNameIncludesPort() {
            var config = new LdapConfig { Server = "dc01.corp.com", ForceSSL = true, SSLPort = 1636 };
            var (contextName, _) = LdapUtils.BuildPrincipalContextParameters(config);
            Assert.Equal("dc01.corp.com:1636", contextName);
        }

        // ---------------------------------------------------------------------------
        // ContextOptions – mirroring connection pool's mutual-exclusion rule
        // ---------------------------------------------------------------------------

        [Fact]
        public void BuildPrincipalContextParameters_Default_HasNegotiateSigningAndSealing() {
            var (_, options) = LdapUtils.BuildPrincipalContextParameters(new LdapConfig());
            var expected = ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing;
            Assert.Equal(expected, options);
        }

        [Fact]
        public void BuildPrincipalContextParameters_ForceSSL_HasNegotiateAndSSLOnly_NoSigningOrSealing() {
            var config = new LdapConfig { ForceSSL = true };
            var (_, options) = LdapUtils.BuildPrincipalContextParameters(config);
            var expected = ContextOptions.Negotiate | ContextOptions.SecureSocketLayer;
            Assert.Equal(expected, options);
            Assert.Equal((ContextOptions)0, options & ContextOptions.Signing);
            Assert.Equal((ContextOptions)0, options & ContextOptions.Sealing);
        }

        [Fact]
        public void BuildPrincipalContextParameters_DisableSigning_HasNegotiateOnly() {
            var config = new LdapConfig { DisableSigning = true };
            var (_, options) = LdapUtils.BuildPrincipalContextParameters(config);
            Assert.Equal(ContextOptions.Negotiate, options);
        }

        [Fact]
        public void BuildPrincipalContextParameters_ForceSSLAndDisableSigning_HasNegotiateAndSSLOnly() {
            var config = new LdapConfig { ForceSSL = true, DisableSigning = true };
            var (_, options) = LdapUtils.BuildPrincipalContextParameters(config);
            var expected = ContextOptions.Negotiate | ContextOptions.SecureSocketLayer;
            Assert.Equal(expected, options);
        }

        #endregion

        [Fact]
        public async Task Test_ResolveHostToSid_BlankHost() {
            var spn = "MSSQLSvc/:1433";
            var utils = new LdapUtils();

            var (success, sid) = await utils.ResolveHostToSid(spn, "");
            Assert.False(success);
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task EnterpriseDomainControllersGroup_CorrectValues() {
            var utilsMock = new Mock<LdapUtils>();
            
            //We're going to say TESTLAB.LOCAL is forest root, and SECONDARY is a child domain underneath TESTLAB.LOCAL

            utilsMock.Setup(x => x.GetDomainNameFromSid("S-1-5-21-3130019616-2776909439-2417379446"))
                .ReturnsAsync((true, "TESTLAB.LOCAL"));
            utilsMock.Setup(x => x.GetDomainNameFromSid("S-1-5-21-3130019616-2776909439-2417379447"))
                .ReturnsAsync((true, "SECONDARY.TESTLAB.LOCAL"));

            utilsMock.Setup(x => x.GetForest("TESTLAB.LOCAL")).ReturnsAsync((true, "TESTLAB.LOCAL"));
            utilsMock.Setup(x => x.GetForest("SECONDARY.TESTLAB.LOCAL")).ReturnsAsync((true, "TESTLAB.LOCAL"));
            
            utilsMock.Setup(x => x.GetDomainSidFromDomainName("TESTLAB.LOCAL")).ReturnsAsync((true, "S-1-5-21-3130019616-2776909439-2417379446"));

            var utils = utilsMock.Object;
            utils.AddDomainController("S-1-5-21-3130019616-2776909439-2417379446-2105");
            utils.AddDomainController("S-1-5-21-3130019616-2776909439-2417379446-2106");
            utils.AddDomainController("S-1-5-21-3130019616-2776909439-2417379447-2105");

            var result = await utils.GetWellKnownPrincipalOutput().ToArrayAsync();
            Assert.Single(result);
            var entDCGroup = result[0] as Group;
            Assert.Equal("TESTLAB.LOCAL-S-1-5-9", entDCGroup.ObjectIdentifier);
            Assert.Equal(3, entDCGroup.Members.Length);
        }
    }
}
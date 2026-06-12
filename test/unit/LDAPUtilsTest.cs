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

            return TestPrivateMethod.StaticMethod<IDirectoryObject>(typeof(Helpers),
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

        // ---------------------------------------------------------------------------
        // AllowFallbackToUncontrolledLdap gate and DomainInfo resolution
        // ---------------------------------------------------------------------------

        [Fact]
        public void LdapConfig_AllowFallbackToUncontrolledLdap_DefaultsToFalse() {
            var config = new LdapConfig();
            Assert.False(config.AllowFallbackToUncontrolledLdap);
        }

        [Fact]
        public void LdapConfig_ToString_IncludesAllowFallbackFlag() {
            var offConfig = new LdapConfig();
            Assert.Contains("AllowFallbackToUncontrolledLdap: False", offConfig.ToString());

            var onConfig = new LdapConfig { AllowFallbackToUncontrolledLdap = true };
            Assert.Contains("AllowFallbackToUncontrolledLdap: True", onConfig.ToString());
        }

        [Fact]
        public void LdapConfig_CurrentUserDomain_DefaultsToNull() {
            var config = new LdapConfig();
            Assert.Null(config.CurrentUserDomain);
        }

        [Fact]
        public void LdapConfig_ToString_IncludesCurrentUserDomain_WhenSet() {
            var unset = new LdapConfig();
            Assert.DoesNotContain("CurrentUserDomain:", unset.ToString());

            var set = new LdapConfig { CurrentUserDomain = "CONTOSO.LOCAL" };
            Assert.Contains("CurrentUserDomain: CONTOSO.LOCAL", set.ToString());
        }

        [Fact]
        public async Task GetDomainInfoAsync_ControlledPathFails_FallbackDisabled_ReturnsFailure() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });

            var (success, info) = await utils.GetDomainInfoAsync("unreachable.invalid.test");
            Assert.False(success);
            Assert.Null(info);
        }

        [Fact]
        public void GetDomain_OutDomain_ReturnsFalse_WhenFallbackDisabled() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { AllowFallbackToUncontrolledLdap = false });

            Assert.False(utils.GetDomain(out var currentDomain));
            Assert.Null(currentDomain);

            Assert.False(utils.GetDomain("unreachable.invalid.test", out var namedDomain));
            Assert.Null(namedDomain);

            Assert.False(LdapUtils.GetDomain("unreachable.invalid.test",
                new LdapConfig { AllowFallbackToUncontrolledLdap = false }, out var staticDomain));
            Assert.Null(staticDomain);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void GetDomain_Static_ReturnsFalse_WithoutThrowing_OnBlankName(string domainName) {
            // ConcurrentDictionary throws on null keys, so the static overload would previously
            // crash on a null hint. The static has no per-instance null-resolution cache to fall
            // back on, so blank inputs are rejected up front.
            var config = new LdapConfig { AllowFallbackToUncontrolledLdap = true };

            var success = LdapUtils.GetDomain(domainName, config, out var domain);

            Assert.False(success);
            Assert.Null(domain);
        }

        // ---------------------------------------------------------------------------
        // TryStripNtdsSettingsPrefix
        // ---------------------------------------------------------------------------

        [Fact]
        public void TryStripNtdsSettingsPrefix_StandardDn_StripsPrefixAndReturnsServerDn() {
            const string input =
                "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=local";
            var ok = LdapUtils.TryStripNtdsSettingsPrefix(input, out var serverDn);
            Assert.True(ok);
            Assert.Equal(
                "CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=local",
                serverDn);
        }

        [Fact]
        public void TryStripNtdsSettingsPrefix_LowercasePrefix_StripsCaseInsensitively() {
            const string input = "cn=ntds settings,CN=DC01,CN=Servers,DC=contoso,DC=local";
            var ok = LdapUtils.TryStripNtdsSettingsPrefix(input, out var serverDn);
            Assert.True(ok);
            Assert.Equal("CN=DC01,CN=Servers,DC=contoso,DC=local", serverDn);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void TryStripNtdsSettingsPrefix_NullOrEmptyInput_ReturnsFalse(string input) {
            var ok = LdapUtils.TryStripNtdsSettingsPrefix(input, out var serverDn);
            Assert.False(ok);
            Assert.Null(serverDn);
        }

        [Fact]
        public void TryStripNtdsSettingsPrefix_MissingPrefix_ReturnsFalse() {
            const string input = "CN=DC01,CN=Servers,DC=contoso,DC=local";
            var ok = LdapUtils.TryStripNtdsSettingsPrefix(input, out var serverDn);
            Assert.False(ok);
            Assert.Null(serverDn);
        }

        [Fact]
        public void TryStripNtdsSettingsPrefix_PrefixOnly_ReturnsFalse() {
            const string input = "CN=NTDS Settings,";
            var ok = LdapUtils.TryStripNtdsSettingsPrefix(input, out var serverDn);
            Assert.False(ok);
            Assert.Equal(string.Empty, serverDn);
        }

        // ---------------------------------------------------------------------------
        // ResolveEffectiveDomainHint
        // ---------------------------------------------------------------------------

        [Fact]
        public void ResolveEffectiveDomainHint_ExplicitDomain_WinsOverCurrentUserDomain() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { CurrentUserDomain = "FALLBACK.LOCAL" });

            Assert.Equal("EXPLICIT.LOCAL", utils.ResolveEffectiveDomainHint("EXPLICIT.LOCAL"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void ResolveEffectiveDomainHint_NullOrWhitespaceInput_FallsBackToCurrentUserDomain(string input) {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { CurrentUserDomain = "CONTOSO.LOCAL" });

            Assert.Equal("CONTOSO.LOCAL", utils.ResolveEffectiveDomainHint(input));
        }

        [Fact]
        public void ResolveEffectiveDomainHint_WhitespaceCurrentUserDomain_FallsThroughToEnvironment() {
            var utils = new LdapUtils();
            utils.SetLdapConfig(new LdapConfig { CurrentUserDomain = "   " });

            // Cannot assert a literal without pinning Environment.UserDomainName; asserting
            // that the whitespace CurrentUserDomain was skipped and something else was chosen
            // is sufficient to cover the branch.
            var result = utils.ResolveEffectiveDomainHint(null);
            Assert.False(string.IsNullOrWhiteSpace(result));
            Assert.NotEqual("   ", result);
        }

        // ---------------------------------------------------------------------------
        // DomainInfo.CompletenessScore / CacheDomainInfo (H-1 regression coverage)
        // ---------------------------------------------------------------------------

        [Fact]
        public void CompletenessScore_EmptyInfo_ReturnsZero() {
            Assert.Equal(0, new DomainInfo().CompletenessScore());
        }

        [Fact]
        public void CompletenessScore_AllFieldsPopulated_ReturnsSeven() {
            var info = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                forestName: "CONTOSO.LOCAL",
                domainSid: "S-1-5-21-1-2-3",
                netBiosName: "CONTOSO",
                primaryDomainController: "dc01.contoso.local",
                domainControllers: new[] { "dc01.contoso.local" });
            Assert.Equal(7, info.CompletenessScore());
        }

        [Fact]
        public void CompletenessScore_EmptyDomainControllersList_ContributesZero() {
            var info = new DomainInfo(name: "CONTOSO.LOCAL", domainControllers: Array.Empty<string>());
            Assert.Equal(1, info.CompletenessScore());
        }

        [Fact]
        public void CompletenessScore_EmptyStringFields_ContributeZero() {
            var info = new DomainInfo(name: "", distinguishedName: "", forestName: "");
            Assert.Equal(0, info.CompletenessScore());
        }

        [Fact]
        public async Task CacheDomainInfo_RicherRecordReplacesSparserRecord() {
            new LdapUtils().ResetUtils();
            const string key = "completeness-upgrade.test";

            // Sparse record like the one-shot direct-LDAP tier produces (no NetBiosName).
            var sparse = new DomainInfo(
                name: "COMPLETENESS-UPGRADE.TEST",
                distinguishedName: "DC=completeness-upgrade,DC=test",
                domainSid: "S-1-5-21-1-2-3");
            LdapUtils.CacheDomainInfo(key, sparse);

            // Rich record like the pool-driven controlled tier produces.
            var rich = new DomainInfo(
                name: "COMPLETENESS-UPGRADE.TEST",
                distinguishedName: "DC=completeness-upgrade,DC=test",
                domainSid: "S-1-5-21-1-2-3",
                netBiosName: "COMPLETE",
                primaryDomainController: "dc01.completeness-upgrade.test",
                domainControllers: new[] { "dc01.completeness-upgrade.test" });
            LdapUtils.CacheDomainInfo(key, rich);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(key, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("COMPLETE", cached.NetBiosName);
            Assert.Equal("dc01.completeness-upgrade.test", cached.PrimaryDomainController);
        }

        [Fact]
        public async Task CacheDomainInfo_SparserRecordDoesNotReplaceRicher() {
            new LdapUtils().ResetUtils();
            const string key = "completeness-no-downgrade.test";

            var rich = new DomainInfo(
                name: "COMPLETENESS-NO-DOWNGRADE.TEST",
                distinguishedName: "DC=completeness-no-downgrade,DC=test",
                domainSid: "S-1-5-21-9-9-9",
                netBiosName: "RICHFIRST",
                primaryDomainController: "dc01.completeness-no-downgrade.test",
                domainControllers: new[] { "dc01.completeness-no-downgrade.test" });
            LdapUtils.CacheDomainInfo(key, rich);

            var sparse = new DomainInfo(
                name: "COMPLETENESS-NO-DOWNGRADE.TEST",
                distinguishedName: "DC=completeness-no-downgrade,DC=test",
                domainSid: "S-1-5-21-9-9-9");
            LdapUtils.CacheDomainInfo(key, sparse);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(key, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("RICHFIRST", cached.NetBiosName);
        }

        [Fact]
        public async Task CacheDomainInfo_EqualScoreDoesNotReplaceExisting() {
            new LdapUtils().ResetUtils();
            const string key = "completeness-equal.test";

            var first = new DomainInfo(name: "COMPLETENESS-EQUAL.TEST", domainSid: "S-1-5-21-1-1-1");
            LdapUtils.CacheDomainInfo(key, first);

            var second = new DomainInfo(name: "COMPLETENESS-EQUAL.TEST", domainSid: "S-1-5-21-2-2-2");
            LdapUtils.CacheDomainInfo(key, second);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(key, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("S-1-5-21-1-1-1", cached.DomainSid);
        }

        [Fact]
        public async Task CacheDomainInfo_NullKeyOrCandidate_NoOp() {
            new LdapUtils().ResetUtils();
            const string key = "completeness-noop.test";

            LdapUtils.CacheDomainInfo(null, new DomainInfo(name: "IGNORED"));
            LdapUtils.CacheDomainInfo(key, null);

            // Static helper should fail through every tier because nothing was cached and the
            // server is unreachable with fallback disabled.
            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(key, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.False(ok);
            Assert.Null(cached);
        }

        [Fact]
        public async Task CacheDomainInfo_KeyMismatchesCandidateName_NoOp() {
            new LdapUtils().ResetUtils();
            const string key = "h2-contoso.test";

            // Simulates a misconfigured LdapConfig.Server pin that lands on a DC outside the
            // requested domain - the candidate's Name describes fabrikam, but the caller asked
            // about contoso. The guard must reject the write to prevent cache poisoning.
            var fabrikam = new DomainInfo(
                name: "H2-FABRIKAM.TEST",
                distinguishedName: "DC=h2-fabrikam,DC=test",
                domainSid: "S-1-5-21-9-9-9",
                netBiosName: "FABRIKAM");
            LdapUtils.CacheDomainInfo(key, fabrikam);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(key, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.False(ok);
            Assert.Null(cached);
        }

        [Fact]
        public async Task CacheDomainInfo_KeyMatchesNetBiosName_Cached() {
            new LdapUtils().ResetUtils();
            const string netBiosKey = "H2NETBIOS";

            // NetBIOS short-name keys are a legitimate alias form - the guard must accept the
            // write when key matches candidate.NetBiosName even though it differs from Name.
            var info = new DomainInfo(
                name: "H2-NETBIOS-MATCH.TEST",
                distinguishedName: "DC=h2-netbios-match,DC=test",
                domainSid: "S-1-5-21-1-1-1",
                netBiosName: "H2NETBIOS");
            LdapUtils.CacheDomainInfo(netBiosKey, info);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(netBiosKey, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("H2-NETBIOS-MATCH.TEST", cached.Name);
        }

        [Fact]
        public async Task CacheDomainInfo_KeyMatchesCandidateNameCaseInsensitive_Cached() {
            new LdapUtils().ResetUtils();
            const string lowerKey = "h2-case.test";

            var info = new DomainInfo(name: "H2-CASE.TEST", domainSid: "S-1-5-21-2-2-2");
            LdapUtils.CacheDomainInfo(lowerKey, info);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(lowerKey, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("S-1-5-21-2-2-2", cached.DomainSid);
        }

        [Fact]
        public async Task CacheDomainInfo_MirrorsEntryUnderCandidateName() {
            new LdapUtils().ResetUtils();
            const string netBiosKey = "H1MIRROR";

            // Write under the NetBIOS alias - the helper must mirror the entry under the
            // canonical DNS Name so a later lookup by FQDN hits the same record without redoing
            // resolution.
            var info = new DomainInfo(
                name: "H1-MIRROR.TEST",
                distinguishedName: "DC=h1-mirror,DC=test",
                domainSid: "S-1-5-21-3-3-3",
                netBiosName: "H1MIRROR");
            LdapUtils.CacheDomainInfo(netBiosKey, info);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync("H1-MIRROR.TEST", new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("H1MIRROR", cached.NetBiosName);
            Assert.Equal("S-1-5-21-3-3-3", cached.DomainSid);
        }

        [Fact]
        public async Task CacheDomainInfo_RicherAliasWriteUpgradesNameKeyEntry() {
            new LdapUtils().ResetUtils();
            const string fqdnKey = "h1-upgrade.test";
            const string netBiosKey = "H1UPGRADE";

            // Pre-seed the canonical-Name entry with a sparse record (e.g. an earlier ADSI tier
            // result). A later richer write under the NetBIOS alias must propagate through the
            // mirror so a FQDN lookup observes the upgrade rather than the stale sparse entry.
            var sparse = new DomainInfo(name: "H1-UPGRADE.TEST", domainSid: "S-1-5-21-4-4-4");
            LdapUtils.CacheDomainInfo(fqdnKey, sparse);

            var rich = new DomainInfo(
                name: "H1-UPGRADE.TEST",
                distinguishedName: "DC=h1-upgrade,DC=test",
                domainSid: "S-1-5-21-4-4-4",
                netBiosName: "H1UPGRADE",
                primaryDomainController: "dc01.h1-upgrade.test",
                domainControllers: new[] { "dc01.h1-upgrade.test" });
            LdapUtils.CacheDomainInfo(netBiosKey, rich);

            var (ok, cached) = await LdapUtils.GetDomainInfoStaticAsync(fqdnKey, new LdapConfig {
                Server = "unreachable.invalid.test",
                AllowFallbackToUncontrolledLdap = false
            });
            Assert.True(ok);
            Assert.Equal("H1UPGRADE", cached.NetBiosName);
            Assert.Equal("dc01.h1-upgrade.test", cached.PrimaryDomainController);
        }

        // ---------------------------------------------------------------------------
        // SelectRicherDomainInfo / TryEnrichDomainInfoViaDirectLdapAsync coverage
        // ---------------------------------------------------------------------------

        [Fact]
        public void SelectRicherDomainInfo_NullEnriched_ReturnsSeed() {
            var seed = new DomainInfo(name: "CONTOSO.LOCAL", domainSid: "S-1-5-21-1-2-3");
            Assert.Same(seed, LdapUtils.SelectRicherDomainInfo(seed, null));
        }

        [Fact]
        public void SelectRicherDomainInfo_NullSeed_ReturnsEnriched() {
            var enriched = new DomainInfo(name: "CONTOSO.LOCAL");
            Assert.Same(enriched, LdapUtils.SelectRicherDomainInfo(null, enriched));
        }

        [Fact]
        public void SelectRicherDomainInfo_NameMismatch_ReturnsSeed() {
            var seed = new DomainInfo(name: "CONTOSO.LOCAL", domainSid: "S-1-5-21-1-2-3");
            // Enriched is technically richer but describes a different domain - the guard must
            // reject it to prevent caching the wrong SID/NetBIOS under the seed's cache key.
            var enriched = new DomainInfo(
                name: "FABRIKAM.LOCAL",
                distinguishedName: "DC=fabrikam,DC=local",
                forestName: "FABRIKAM.LOCAL",
                domainSid: "S-1-5-21-9-9-9",
                netBiosName: "FABRIKAM",
                primaryDomainController: "dc01.fabrikam.local",
                domainControllers: new[] { "dc01.fabrikam.local" });
            Assert.Same(seed, LdapUtils.SelectRicherDomainInfo(seed, enriched));
        }

        [Fact]
        public void SelectRicherDomainInfo_NameDiffersOnlyInCase_AcceptsEnriched() {
            var seed = new DomainInfo(name: "CONTOSO.LOCAL", domainSid: "S-1-5-21-1-2-3");
            var enriched = new DomainInfo(
                name: "contoso.local",
                distinguishedName: "DC=contoso,DC=local",
                domainSid: "S-1-5-21-1-2-3",
                netBiosName: "CONTOSO");
            Assert.Same(enriched, LdapUtils.SelectRicherDomainInfo(seed, enriched));
        }

        [Fact]
        public void SelectRicherDomainInfo_LowerScore_ReturnsSeed() {
            var seed = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                domainSid: "S-1-5-21-1-2-3");
            var enriched = new DomainInfo(name: "CONTOSO.LOCAL");
            Assert.Same(seed, LdapUtils.SelectRicherDomainInfo(seed, enriched));
        }

        [Fact]
        public void SelectRicherDomainInfo_EqualScore_ReturnsSeed() {
            var seed = new DomainInfo(name: "CONTOSO.LOCAL", domainSid: "S-1-5-21-1-2-3");
            var enriched = new DomainInfo(name: "CONTOSO.LOCAL", domainSid: "S-1-5-21-9-9-9");
            Assert.Same(seed, LdapUtils.SelectRicherDomainInfo(seed, enriched));
        }

        [Fact]
        public void SelectRicherDomainInfo_HigherScore_ReturnsEnriched() {
            var seed = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                domainSid: "S-1-5-21-1-2-3",
                primaryDomainController: "dc01.contoso.local");
            var enriched = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                forestName: "CONTOSO.LOCAL",
                domainSid: "S-1-5-21-1-2-3",
                netBiosName: "CONTOSO",
                primaryDomainController: "dc01.contoso.local",
                domainControllers: new[] { "dc01.contoso.local" });
            Assert.Same(enriched, LdapUtils.SelectRicherDomainInfo(seed, enriched));
        }

        [Fact]
        public async Task TryEnrichDomainInfoViaDirectLdapAsync_NullSeed_ReturnsNull() {
            var result = await LdapUtils.TryEnrichDomainInfoViaDirectLdapAsync(
                "CONTOSO.LOCAL", null, new LdapConfig(), log: null);
            Assert.Null(result);
        }

        [Fact]
        public async Task TryEnrichDomainInfoViaDirectLdapAsync_FullScoreSeed_ReturnsSeedWithoutBinding() {
            // A score-7 seed with PDC pointing at an unreachable host - if the helper attempted
            // a bind it would either time out or fail; returning the seed identity proves the
            // fast-path skipped the bind entirely.
            var seed = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                forestName: "CONTOSO.LOCAL",
                domainSid: "S-1-5-21-1-2-3",
                netBiosName: "CONTOSO",
                primaryDomainController: "unreachable.invalid.test",
                domainControllers: new[] { "unreachable.invalid.test" });
            var result = await LdapUtils.TryEnrichDomainInfoViaDirectLdapAsync(
                "CONTOSO.LOCAL", seed, new LdapConfig(), log: null);
            Assert.Same(seed, result);
        }

        [Fact]
        public async Task TryEnrichDomainInfoViaDirectLdapAsync_NoBindTarget_ReturnsSeed() {
            // No PrimaryDomainController, no DomainControllers - nothing to bind to, helper must
            // return the seed without attempting any network I/O.
            var seed = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                domainSid: "S-1-5-21-1-2-3");
            var result = await LdapUtils.TryEnrichDomainInfoViaDirectLdapAsync(
                "CONTOSO.LOCAL", seed, new LdapConfig(), log: null);
            Assert.Same(seed, result);
        }

        [Fact]
        public async Task TryEnrichDomainInfoViaDirectLdapAsync_NullConfig_ReturnsSeed() {
            var seed = new DomainInfo(
                name: "CONTOSO.LOCAL",
                primaryDomainController: "dc01.contoso.local");
            var result = await LdapUtils.TryEnrichDomainInfoViaDirectLdapAsync(
                "CONTOSO.LOCAL", seed, config: null, log: null);
            Assert.Same(seed, result);
        }

        [Fact]
        public async Task TryEnrichDomainInfoViaDirectLdapAsync_ServerPinned_BindFailureReturnsSeed() {
            // LdapConfig.Server pins all LDAP traffic to the configured host. Enrichment honors the
            // pin by binding to config.Server rather than the seed's discovered PDC. When the pinned
            // host is unreachable the bind fails and the seed is returned unchanged - this covers
            // both the pin-respect and the bind-failure-fallback paths in one assertion.
            var seed = new DomainInfo(
                name: "CONTOSO.LOCAL",
                distinguishedName: "DC=contoso,DC=local",
                domainSid: "S-1-5-21-1-2-3",
                primaryDomainController: "seed-pdc.invalid.test");
            var config = new LdapConfig { Server = "pinned-server.invalid.test" };
            var result = await LdapUtils.TryEnrichDomainInfoViaDirectLdapAsync(
                "CONTOSO.LOCAL", seed, config, log: null);
            Assert.Same(seed, result);
        }

        // ---------------------------------------------------------------------------
        // ResolveOneShotBindTarget
        // ---------------------------------------------------------------------------

        [Fact]
        public void ResolveOneShotBindTarget_ServerSet_OverridesDomainName() {
            var config = new LdapConfig { Server = "dc01.contoso.local" };
            Assert.Equal("dc01.contoso.local",
                LdapUtils.ResolveOneShotBindTarget("CONTOSO.LOCAL", config));
        }

        [Fact]
        public void ResolveOneShotBindTarget_ServerNull_FallsBackToDomainName() {
            var config = new LdapConfig { Server = null };
            Assert.Equal("CONTOSO.LOCAL",
                LdapUtils.ResolveOneShotBindTarget("CONTOSO.LOCAL", config));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void ResolveOneShotBindTarget_ServerWhitespace_FallsBackToDomainName(string server) {
            var config = new LdapConfig { Server = server };
            Assert.Equal("CONTOSO.LOCAL",
                LdapUtils.ResolveOneShotBindTarget("CONTOSO.LOCAL", config));
        }

        [Fact]
        public void ResolveOneShotBindTarget_NullConfig_ReturnsDomainName() {
            Assert.Equal("CONTOSO.LOCAL",
                LdapUtils.ResolveOneShotBindTarget("CONTOSO.LOCAL", config: null));
        }

    }
}

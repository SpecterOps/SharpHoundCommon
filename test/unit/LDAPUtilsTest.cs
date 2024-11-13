using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
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
        public async Task Test_ResolveHostToSid_BlankHost() {
            var spn = "MSSQLSvc/:1433";
            var utils = new LdapUtils();

            var (success, sid) = await utils.ResolveHostToSid(spn, "");
            Assert.False(success);
        }

        [WindowsOnlyFact]
        public async Task EnterpriseDomainControllersGroup_CorrectValues() {
            var utilsMock = new Mock<LdapUtils>();
            
            //We're going to say TESTLAB.LOCAL is forest root, and SECONDARY is a child domain underneath TESTLAB.LOCAL

            utilsMock.Setup(x => x.GetDomainNameFromSid("S-1-5-21-3130019616-2776909439-2417379446-2105"))
                .ReturnsAsync((true, "TESTLAB.LOCAL"));
            utilsMock.Setup(x => x.GetDomainNameFromSid("S-1-5-21-3130019616-2776909439-2417379446-2106"))
                .ReturnsAsync((true, "TESTLAB.LOCAL"));
            utilsMock.Setup(x => x.GetDomainNameFromSid("S-1-5-21-3130019616-2776909439-2417379447-2105"))
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
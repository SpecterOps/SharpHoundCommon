using System.Collections.Generic;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;

namespace CommonLibTest
{
    public class SiteProcessorTest
    {
        private const string TestGPLinkString =
            "[LDAP://cn={94DD0260-38B5-497E-8876-10E7A96E80D0},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={C52F168C-CD05-4487-B405-564934DA8EFF},cn=policies,cn=system,DC=testlab,DC=local;2]";

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task SiteProcessor_GetContainingSiteForSubnet_InvalidSiteObject_ReturnsFalse(string siteObject)
        {
            var utils = new Mock<ILdapUtils>(MockBehavior.Strict);
            var processor = new SiteProcessor(utils.Object);

            var (success, principal) = await processor.GetContainingSiteForSubnet(new Dictionary<string, object>
            {
                ["siteObject"] = siteObject
            });

            Assert.False(success);
            Assert.Null(principal);
            utils.Verify(x => x.ResolveDistinguishedName(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task SiteProcessor_GetContainingSiteForSubnet_ValidSiteObject_ResolvesDistinguishedName()
        {
            const string siteObject = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=local";
            var expected = new TypedPrincipal("TESTLAB.LOCAL-SITE", Label.Site);
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.ResolveDistinguishedName(siteObject)).ReturnsAsync((true, expected));
            var processor = new SiteProcessor(utils.Object);

            var (success, principal) = await processor.GetContainingSiteForSubnet(new Dictionary<string, object>
            {
                ["siteObject"] = siteObject
            });

            Assert.True(success);
            Assert.Equal(expected, principal);
            utils.Verify(x => x.ResolveDistinguishedName(siteObject), Times.Once);
        }

        [Fact]
        public async Task SiteProcessor_GetContainingSiteForServer_NoDistinguishedName_ReturnsFalse()
        {
            var utils = new Mock<ILdapUtils>(MockBehavior.Strict);
            var processor = new SiteProcessor(utils.Object);
            var entry = new MockDirectoryObject("", new Dictionary<string, object>(), "", "");

            var (success, principal) = await processor.GetContainingSiteForServer(entry);

            Assert.False(success);
            Assert.Null(principal);
            utils.Verify(x => x.ResolveDistinguishedName(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task SiteProcessor_GetContainingSiteForServer_ValidDistinguishedName_ResolvesParentSite()
        {
            const string serverDn = "CN=PRIMARY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=local";
            const string siteDn = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=local";
            var expected = new TypedPrincipal("TESTLAB.LOCAL-SITE", Label.Site);
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.ResolveDistinguishedName(siteDn)).ReturnsAsync((true, expected));
            var processor = new SiteProcessor(utils.Object);

            var (success, principal) = await processor.GetContainingSiteForServer(serverDn);

            Assert.True(success);
            Assert.Equal(expected, principal);
            utils.Verify(x => x.ResolveDistinguishedName(siteDn), Times.Once);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task SiteProcessor_GetReferencedComputerForServer_InvalidServerReference_ReturnsFalse(string serverReference)
        {
            var utils = new Mock<ILdapUtils>(MockBehavior.Strict);
            var processor = new SiteProcessor(utils.Object);

            var (success, principal) = await processor.GetReferencedComputerForServer(new Dictionary<string, object>
            {
                [LDAPProperties.ServerReference] = serverReference
            });

            Assert.False(success);
            Assert.Null(principal);
            utils.Verify(x => x.ResolveDistinguishedName(It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task SiteProcessor_GetReferencedComputerForServer_ValidServerReference_ResolvesComputer()
        {
            const string serverReference = "CN=PRIMARY,OU=DOMAIN CONTROLLERS,DC=TESTLAB,DC=LOCAL";
            var expected = new TypedPrincipal("S-1-5-21-3130019616-2776909439-2417379446-1001", Label.Computer);
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.ResolveDistinguishedName(serverReference)).ReturnsAsync((true, expected));
            var processor = new SiteProcessor(utils.Object);

            var (success, principal) = await processor.GetReferencedComputerForServer(new Dictionary<string, object>
            {
                [LDAPProperties.ServerReference] = serverReference
            });

            Assert.True(success);
            Assert.Equal(expected, principal);
            utils.Verify(x => x.ResolveDistinguishedName(serverReference), Times.Once);
        }

        [Fact]
        public async Task SiteProcessor_GetReferencedComputerForServer_NonComputerReference_ReturnsFalse()
        {
            const string serverReference = "CN=ADMINISTRATORS,CN=BUILTIN,DC=TESTLAB,DC=LOCAL";
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.ResolveDistinguishedName(serverReference))
                .ReturnsAsync((true, new TypedPrincipal("TESTLAB.LOCAL-S-1-5-32-544", Label.Group)));
            var processor = new SiteProcessor(utils.Object);

            var (success, principal) = await processor.GetReferencedComputerForServer(serverReference);

            Assert.False(success);
            Assert.Null(principal);
            utils.Verify(x => x.ResolveDistinguishedName(serverReference), Times.Once);
        }

        [Fact]
        public async Task SiteProcessor_GetReferencedComputerForServer_DirectoryObject_UsesServerReference()
        {
            const string serverReference = "CN=PRIMARY,OU=DOMAIN CONTROLLERS,DC=TESTLAB,DC=LOCAL";
            var processor = new SiteProcessor(new MockLdapUtils());
            var entry = new MockDirectoryObject("", new Dictionary<string, object>
            {
                [LDAPProperties.ServerReference] = serverReference
            }, "", "");

            var (success, principal) = await processor.GetReferencedComputerForServer(entry);

            Assert.True(success);
            Assert.Equal(new TypedPrincipal("S-1-5-21-3130019616-2776909439-2417379446-1001", Label.Computer), principal);
        }

        [Fact]
        public void SiteServer_SeverIs_EdgeNameMatchesOutputProperty()
        {
            Assert.Equal(nameof(SiteServer.SeverIs), EdgeNames.SeverIs);
        }

        [Fact]
        public async Task SiteProcessor_ReadSiteGPLinks_IgnoresNull()
        {
            var processor = new SiteProcessor(new MockLdapUtils());

            var test = await processor.ReadSiteGPLinks(null).ToArrayAsync();

            Assert.Empty(test);
        }

        [Fact]
        public async Task SiteProcessor_ReadSiteGPLinks_UnresolvedGPLink_IsIgnored()
        {
            var processor = new SiteProcessor(new MockLdapUtils());
            const string gpLink =
                "[LDAP://cn={94DD0260-38B5-497E-8876-ABCDEFG},cn=policies,cn=system,DC=testlab,DC=local;0]";

            var test = await processor.ReadSiteGPLinks(gpLink).ToArrayAsync();

            Assert.Empty(test);
        }

        [Fact]
        public async Task SiteProcessor_ReadSiteGPLinks_ReturnsCorrectValues()
        {
            var processor = new SiteProcessor(new MockLdapUtils());

            var test = await processor.ReadSiteGPLinks(TestGPLinkString).ToArrayAsync();

            var expected = new GPLink[]
            {
                new()
                {
                    GUID = "B39818AF-6349-401A-AE0A-E4972F5BF6D9",
                    IsEnforced = false
                },
                new()
                {
                    GUID = "ACDD64D3-67B3-401F-A6CC-804B3F7B1533",
                    IsEnforced = true
                }
            };

            Assert.Equal(2, test.Length);
            Assert.Equal(expected, test);
        }
    }
}

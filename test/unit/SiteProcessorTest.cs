using System.Collections.Generic;
using System.Threading.Tasks;
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
    }
}

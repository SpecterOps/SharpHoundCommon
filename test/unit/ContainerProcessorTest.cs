using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ContainerProcessorTest : IDisposable
    {
        private readonly string _testGpLinkString;
        private readonly ITestOutputHelper _testOutputHelper;

        public ContainerProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testGpLinkString =
                "[LDAP://cn={94DD0260-38B5-497E-8876-10E7A96E80D0},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={C52F168C-CD05-4487-B405-564934DA8EFF},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={1E860A30-603A-45C7-A768-26EE74BE6D5D},cn=policies,cn=system,DC=testlab,DC=local;0]";
        }

        public void Dispose()
        {
        }

        [Fact]
        public async Task ContainerProcessor_ReadContainerGPLinks_IgnoresNull()
        {
            var processor = new ContainerProcessor(new MockLdapUtils());
            var test = await processor.ReadContainerGPLinks(null).ToArrayAsync();
            Assert.Empty(test);
        }

        [Fact]
        public async Task ContainerProcessor_ReadContainerGPLinks_UnresolvedGPLink_IsIgnored()
        {
            var processor = new ContainerProcessor(new MockLdapUtils());
            //GPLink that doesn't exist
            const string s =
                "[LDAP://cn={94DD0260-38B5-497E-8876-ABCDEFG},cn=policies,cn=system,DC=testlab,DC=local;0]";
            var test = await processor.ReadContainerGPLinks(s).ToArrayAsync();
            Assert.Empty(test);
        }

        [Fact]
        public async Task ContainerProcessor_ReadContainerGPLinks_ReturnsCorrectValues()
        {
            var processor = new ContainerProcessor(new MockLdapUtils());
            var test = await processor.ReadContainerGPLinks(_testGpLinkString).ToArrayAsync();

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
                    IsEnforced = false
                },
                new()
                {
                    GUID = "C45E9585-4932-4C03-91A8-1856869D49AF",
                    IsEnforced = false
                }
            };

            Assert.Equal(3, test.Length);
            Assert.Equal(expected, test);
        }

        [Fact]
        public async Task ContainerProcessor_GetContainerChildObjects_ReturnsCorrectData()
        {
            var mock = new Mock<MockLdapUtils>();

            var searchResults = new[]
            {
                //These first 4 should be filtered by our DN filters
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject(
                    "CN=7868d4c8-ac41-4e05-b401-776280e8e9f1,CN=Operations,CN=DomainUpdates,CN=System,DC=testlab,DC=local"
                    , null, null,null)),
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN=Microsoft,CN=Program Data,DC=testlab,DC=local", null, null,null)),
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN=Operations,CN=DomainUpdates,CN=System,DC=testlab,DC=local", null, null,null)),
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN=User,CN={C52F168C-CD05-4487-B405-564934DA8EFF},CN=Policies,CN=System,DC=testlab,DC=local", null,
                    null,null)),
                //This is a real object in our mock
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, "","ECAD920E-8EB1-4E31-A80E-DD36367F81F4")),
                //This object does not exist in our mock
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, "","ECAD920E-8EB1-4E31-A80E-DD36367F81FD")),
                //Test null objectid
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, null, ""))
            };

            mock.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>())).Returns(searchResults.ToAsyncEnumerable);

            var processor = new ContainerProcessor(mock.Object);
            var test = await processor.GetContainerChildObjects(_testGpLinkString).ToArrayAsync();

            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "ECAD920E-8EB1-4E31-A80E-DD36367F81F4",
                    ObjectType = Label.Container
                }
            };

            Assert.Equal(expected, test);
            Assert.Single(test);
            
        }

        [Fact]
        public async Task ContainerProcessor_GetContainerChildObjects_QueryIncludesAdditionalContainerClasses()
        {
            var mock = new Mock<MockLdapUtils>();
            LdapQueryParameters queryParameters = null;
            mock.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>()))
                .Callback<LdapQueryParameters, CancellationToken>((parameters, _) => queryParameters = parameters)
                .Returns(Array.Empty<LdapResult<IDirectoryObject>>().ToAsyncEnumerable);

            var processor = new ContainerProcessor(mock.Object);

            await processor.GetContainerChildObjects("DC=testlab,DC=local").ToArrayAsync();

            Assert.NotNull(queryParameters);
            Assert.Contains("(objectClass=builtinDomain)", queryParameters.LDAPFilter);
            Assert.Contains("(objectClass=sitesContainer)", queryParameters.LDAPFilter);
        }

        [Fact]
        public void ContainerProcessor_ReadBlocksInheritance_ReturnsCorrectValues()
        {
            var test = ContainerProcessor.ReadBlocksInheritance(null);
            var test2 = ContainerProcessor.ReadBlocksInheritance("3");
            var test3 = ContainerProcessor.ReadBlocksInheritance("1");

            Assert.False(test);
            Assert.False(test2);
            Assert.True(test3);
        }

        [Fact]
        public async Task ContainerProcessor_GetContainingObject_ExpectedResult()
        {
            var utils = new MockLdapUtils();
            var proc = new ContainerProcessor(utils);

            var (success, result) = await proc.GetContainingObject("OU=TESTOU,DC=TESTLAB,DC=LOCAL");
            Assert.Equal(Label.Domain, result.ObjectType);
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446", result.ObjectIdentifier);
            Assert.True(success);

            (success, result) = await proc.GetContainingObject("CN=PRIMARY,OU=DOMAIN CONTROLLERS,DC=TESTLAB,DC=LOCAL");
            Assert.Equal(Label.OU, result.ObjectType);
            Assert.Equal("0DE400CD-2FF3-46E0-8A26-2C917B403C65", result.ObjectIdentifier);
            Assert.True(success);

            (success, result) = await proc.GetContainingObject("CN=ADMINISTRATORS,CN=BUILTIN,DC=TESTLAB,DC=LOCAL");
            Assert.Equal(Label.Container, result.ObjectType);
            Assert.Equal(MockLdapUtils.BuiltinContainerGuid, result.ObjectIdentifier);
            Assert.True(success);
        }

        [Fact]
        public async Task ContainerProcessor_GetContainingObject_BadDN_ReturnsNull()
        {
            var utils = new MockLdapUtils();
            var proc = new ContainerProcessor(utils);

            var (success, result) = await proc.GetContainingObject("abc123");
            Assert.False(success);
        }
    }
}

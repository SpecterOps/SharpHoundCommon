using System;
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
    public class GroupProcessorTest
    {
        private readonly Result<string>[] _testMembershipReturn =
        {
            Result<string>.Ok("CN=Domain Admins,CN=Users,DC=testlab,DC=local"),
            Result<string>.Ok("CN=Enterprise Admins,CN=Users,DC=testlab,DC=local"),
            Result<string>.Ok("CN=Administrator,CN=Users,DC=testlab,DC=local"),
            Result<string>.Ok("CN=NonExistent,CN=Users,DC=testlab,DC=local")
        };
        
        private readonly string[] _testMembership =
        {
            "CN=Domain Admins,CN=Users,DC=testlab,DC=local",
            "CN=Enterprise Admins,CN=Users,DC=testlab,DC=local",
            "CN=Administrator,CN=Users,DC=testlab,DC=local",
            "CN=NonExistent,CN=Users,DC=testlab,DC=local"
        };
        
        private readonly Result<string>[] _testMembershipReturnFail =
        {
            Result<string>.Fail()
        };
        

        private readonly ITestOutputHelper _testOutputHelper;
        private GroupProcessor _baseProcessor;

        public GroupProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _baseProcessor = new GroupProcessor(new LdapUtils());
        }

        [Fact]
        public void GroupProcessor_GetPrimaryGroupInfo_NullPrimaryGroupID_ReturnsNull()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo(null, null);
            Assert.Null(result);
        }

        [WindowsOnlyFact]
        public void GroupProcessor_GetPrimaryGroupInfo_ReturnsCorrectSID()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo("513", "S-1-5-21-3130019616-2776909439-2417379446-1105");
            Assert.Equal("S-1-5-21-3130019616-2776909439-2417379446-513", result);
        }

        [Fact]
        public void GroupProcessor_GetPrimaryGroupInfo_BadSID_ReturnsNull()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo("513", "ABC123");
            Assert.Null(result);
        }

        [Fact]
        public async Task GroupProcessor_ReadGroupMembers_EmptyMembers_DoesRangedRetrieval()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-512",
                    ObjectType = Label.Group
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-519",
                    ObjectType = Label.Group
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-500",
                    ObjectType = Label.User
                },
                new()
                {
                    ObjectIdentifier = "CN=NONEXISTENT,CN=USERS,DC=TESTLAB,DC=LOCAL",
                    ObjectType = Label.Base
                }
            };
            mockUtils.Setup(x => x.RangedRetrieval(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(_testMembershipReturn.ToAsyncEnumerable());
            var processor = new GroupProcessor(mockUtils.Object);

            var results = await processor
                .ReadGroupMembers("CN=Administrators,CN=Builtin,DC=testlab,DC=local", Array.Empty<string>()).ToArrayAsync();
            foreach (var t in results) _testOutputHelper.WriteLine(t.ToString());
            Assert.Equal(4, results.Length);
            Assert.Equal(expected, results);
        }

        [WindowsOnlyFact]
        public async Task GroupProcessor_ReadGroupMembers_ReturnsCorrectMembers()
        {
            var utils = new MockLdapUtils();
            var processor = new GroupProcessor(utils);
            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-512",
                    ObjectType = Label.Group
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-519",
                    ObjectType = Label.Group
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-500",
                    ObjectType = Label.User
                },
                new()
                {
                    ObjectIdentifier = "CN=NONEXISTENT,CN=USERS,DC=TESTLAB,DC=LOCAL",
                    ObjectType = Label.Base
                }
            };

            var results = await processor
                .ReadGroupMembers("CN=Administrators,CN=Builtin,DC=testlab,DC=local", _testMembership).ToArrayAsync();
            foreach (var t in results) _testOutputHelper.WriteLine(t.ToString());
            Assert.Equal(4, results.Length);
            Assert.Equal(expected, results);
        }
        
        [Fact]
        public async Task GroupProcessor_ReadGroupMembers_EmptyMembers_FailRangedRetrieval()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            mockUtils.Setup(x => x.RangedRetrieval(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(_testMembershipReturnFail.ToAsyncEnumerable());
            var processor = new GroupProcessor(mockUtils.Object);

            var results = await processor
                .ReadGroupMembers("CN=Administrators,CN=Builtin,DC=testlab,DC=local", Array.Empty<string>()).ToArrayAsync();
            foreach (var t in results) _testOutputHelper.WriteLine(t.ToString());
            Assert.Empty(results);
        }
        
        [Fact]
        public void GroupProcessor_GetPrimaryGroupInfo_NullObjectID_ReturnsNull()
        {
            var result = GroupProcessor.GetPrimaryGroupInfo("513", null);
            Assert.Null(result);
        }
    }
}
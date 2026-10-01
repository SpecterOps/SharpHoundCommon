using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class DomainTrustProcessorTest
    {
        private ITestOutputHelper _testOutputHelper;

        public DomainTrustProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task DomainTrustProcessor_EnumerateDomainTrusts_HappyPath()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var searchResults = new[]
            {
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityidentifier", Utils.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "",""))
            };

            mockUtils.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>())).Returns(searchResults.ToAsyncEnumerable);
            var processor = new DomainTrustProcessor(mockUtils.Object);
            var test = await processor.EnumerateDomainTrusts("testlab.local").ToArrayAsync();
            Assert.Single(test);
            var trust = test.First();
            Assert.Equal(TrustDirection.Bidirectional, trust.TrustDirection);
            Assert.Equal("EXTERNAL.LOCAL", trust.TargetDomainName);
            Assert.Equal("S-1-5-21-3084884204-958224920-2707782874", trust.TargetDomainSid);
            Assert.True(trust.IsTransitive);
            Assert.Equal(TrustType.Unknown, trust.TrustType);
            Assert.True(trust.SidFilteringEnabled);
        }

        [Fact]
        public async Task DomainTrustProcessor_EnumerateDomainTrusts_SadPaths()
        {
            var mockUtils = new Mock<MockLdapUtils>();
            var searchResults = new[]
            {
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityIdentifier", Array.Empty<byte>()}
                    }, "","")),
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityIdentifier", Utils.B64ToBytes("QQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "","")),
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityIdentifier", Utils.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "","")),
                LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"cn", "external.local"},
                        {"securityIdentifier", Utils.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "",""))
            };

            mockUtils.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>())).Returns(searchResults.ToAsyncEnumerable);
            var processor = new DomainTrustProcessor(mockUtils.Object);
            var test = await processor.EnumerateDomainTrusts("testlab.local").ToArrayAsync();
            Assert.Empty(test);
        }

        [Fact]
        public void DomainTrustProcessor_TrustAttributesToType()
        {
            var attrib = TrustAttributes.WithinForest;
            var test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.Unknown, test);

            attrib = TrustAttributes.ForestTransitive;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.Forest, test);

            attrib = TrustAttributes.TreatAsExternal;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.External, test);

            attrib = TrustAttributes.CrossOrganization;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.External, test);

            attrib = TrustAttributes.QuarantinedDomain;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.External, test);
        }

        [Theory]
        [InlineData(TrustType.ParentChild)]
        [InlineData(TrustType.TreeRoot)]
        [InlineData(TrustType.CrossLink)]
        [InlineData(TrustType.External)]
        [InlineData(TrustType.Forest)]
        [InlineData(TrustType.Kerberos)]
        [InlineData(TrustType.Unknown)]
        public async Task EnumerateDomainTrusts_PreservesResolvedClassification(TrustType classification) {
            var domain = new LdapDomainInfo { Name = "testlab.local", DefaultNamingContext = "DC=testlab,DC=local" };
            domain.TrustTypes["external.local"] = classification;
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.GetDomain("testlab.local", out domain)).Returns(true);
            utils.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>()))
                .Returns(new[] { CreateTrustEntry(2) }.ToAsyncEnumerable);
            var trusts = await new DomainTrustProcessor(utils.Object).EnumerateDomainTrusts("testlab.local").ToArrayAsync();
            Assert.Equal(classification, Assert.Single(trusts).TrustType);
        }

        [Theory]
        [InlineData(2, TrustAttributes.ForestTransitive, TrustType.Forest)]
        [InlineData(2, (TrustAttributes)0, TrustType.External)]
        [InlineData(1, TrustAttributes.QuarantinedDomain, TrustType.External)]
        [InlineData(3, TrustAttributes.WithinForest, TrustType.Kerberos)]
        [InlineData(2, TrustAttributes.WithinForest, TrustType.Unknown)]
        public async Task EnumerateDomainTrusts_UnknownClassificationUsesReadableTrustFields(
            int ldapType, TrustAttributes attributes, TrustType expected) {
            var domain = new LdapDomainInfo { Name = "testlab.local", DefaultNamingContext = "DC=testlab,DC=local" };
            domain.TrustTypes["external.local"] = TrustType.Unknown;
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.GetDomain("testlab.local", out domain)).Returns(true);
            utils.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>()))
                .Returns(new[] { CreateTrustEntry(ldapType, attributes) }.ToAsyncEnumerable);
            var trusts = await new DomainTrustProcessor(utils.Object).EnumerateDomainTrusts("testlab.local").ToArrayAsync();
            Assert.Equal(expected, Assert.Single(trusts).TrustType);
        }

        [Theory]
        [InlineData(1, TrustType.Unknown)]
        [InlineData(2, TrustType.Unknown)]
        [InlineData(3, TrustType.Kerberos)]
        public async Task EnumerateDomainTrusts_MissingTopologyDoesNotGuessParentChild(int ldapType, TrustType expected) {
            var utils = new Mock<ILdapUtils>();
            utils.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>()))
                .Returns(new[] { CreateTrustEntry(ldapType) }.ToAsyncEnumerable);
            var trusts = await new DomainTrustProcessor(utils.Object).EnumerateDomainTrusts("testlab.local").ToArrayAsync();
            Assert.Equal(expected, Assert.Single(trusts).TrustType);
        }

        private static LdapResult<IDirectoryObject> CreateTrustEntry(int ldapType,
            TrustAttributes attributes = TrustAttributes.WithinForest) =>
            LdapResult<IDirectoryObject>.Ok(new MockDirectoryObject("", new Dictionary<string, object> {
                ["trustdirection"] = "3",
                ["trusttype"] = ldapType.ToString(),
                ["trustattributes"] = ((int)attributes).ToString(),
                ["cn"] = "EXTERNAL.LOCAL",
                ["securityidentifier"] = Utils.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")
            }));
    }
}

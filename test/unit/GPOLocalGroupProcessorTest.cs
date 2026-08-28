using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    public class GPOLocalGroupProcessorTest {
        private readonly string GpttmplInfContent = @"[Unicode]
        Unicode=yes
        [Version]
        signature=""$CHICAGO$""
        Revision=1
        [Group Membership]
        *S-1-5-21-3130019616-2776909439-2417379446-514__Memberof = *S-1-5-32-544
        *S-1-5-21-3130019616-2776909439-2417379446-514__Members =
        *S-1-5-32-544__Members = 
        ";

        private readonly string GpttmplInfContentNoMatch = @"[Unicode]
        Unicode=yes
        [Version]
        signature=""$CHICAGO$""
        Revision=1
        ";

        private readonly string GroupXmlContent = @"<?xml version=""1.0"" encoding=""UTF-8""?>
        <Groups clsid=""{3125E937-EB16-4b4c-9934-544FC6D24D26}"">
            <Group clsid=""{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{49951410-3929-4041-AB49-75404B3BBB8A}"" changed=""2019-10-30 00:07:18"" image=""2"" name=""Administrators"">
                <Properties groupName=""Administrators"" groupSid="""" removeAccounts=""0"" deleteAllGroups=""0"" deleteAllUsers=""0"" description="""" newName="""" action=""U"">
                    <Members>
                        <Member name=""TESTLAB\Domain Users"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-513""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
            <Group clsid=""{AD4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{49951410-3929-4041-AB49-75404B3BBB8A}"" changed=""2019-10-30 00:07:18"" image=""2"" name=""Foo"">
                <Properties groupName=""Foo"" groupSid="""" removeAccounts=""0"" deleteAllGroups=""0"" deleteAllUsers=""0"" description="""" newName="""" action=""Z"">
                    <Members>
                        <Member name=""TESTLAB\Domain Users"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-513""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
            <Group clsid=""{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{49951410-3929-4041-AB49-75404B3BBB8A}"" changed=""2019-10-30 00:07:18"" image=""2"" name=""Administrators"">
                <Properties groupName=""Administrators"" groupSid=""S-1-5-32-544"" removeAccounts=""0"" deleteAllGroups=""1"" deleteAllUsers=""1"" description="""" newName="""" action=""U"">
                    <Members>
                        <Member name=""TESTLAB\Domain Users"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-513""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
            <Group clsid=""{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{49951410-3929-4041-AB49-75404B3BBB8A}"" changed=""2019-10-30 00:07:18"" image=""2"" name=""Administrators"">
                <Properties groupName=""Administrators"" groupSid=""S-1-5-32-544"" removeAccounts=""0"" deleteAllGroups=""0"" deleteAllUsers=""0"" description="""" newName="""" action=""U"">
                    <Members>
                        <Member name=""TESTLAB\Domain Users"" action=""ADD"" sid=""""/>
                        <Member name=""GEORGE"" action=""ADD"" sid=""""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
            <Group clsid=""{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"" uid=""{49951410-3929-4041-AB49-75404B3BBB8A}"" changed=""2019-10-30 00:07:18"" image=""2"" name=""Administrators"">
                <Properties groupName=""POKEMON"" groupSid="""" removeAccounts=""0"" deleteAllGroups=""0"" deleteAllUsers=""0"" description="""" newName="""" action=""U"">
                    <Members>
                        <Member name=""TESTLAB\Domain Users"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-513""/>
                        <Member name=""TESTLAB\Domain Computers"" action=""ADD"" sid=""S-1-5-21-3130019616-2776909439-2417379446-515""/>
                    </Members>
                </Properties>
            </Group>
        </Groups>
        ";

        private readonly string GroupXmlContentDisabled = @"<?xml version=""1.0"" encoding=""UTF-8""?>
        <Groups clsid=""{3125E937-EB16-4b4c-9934-544FC6D24D26}"" disabled=""1"">
        </Groups>
        ";

        private ITestOutputHelper _testOutputHelper;

        public GPOLocalGroupProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public async Task GPOLocalGroupProcessorContext_Processors_QueryGPOOnce() {
            var (mockLdapUtils, gpLink, linkDn) = CreateContextTestData();
            using var context = new GPOLocalGroupProcessorContext();
            var processors = Enumerable.Range(0, 50)
                .Select(_ => context.CreateGPOLocalGroupProcessor(mockLdapUtils.Object))
                .ToArray();

            await Task.WhenAll(processors.Select(processor =>
                processor.ReadGPOLocalGroups(gpLink, "DC=TEST,DC=LOCAL")));

            mockLdapUtils.Verify(x => x.Query(
                It.Is<LdapQueryParameters>(parameters =>
                    parameters.LDAPFilter == new LdapFilter().AddAllObjects().GetFilter() &&
                    parameters.SearchBase == linkDn),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task GPOLocalGroupProcessorContext_Processors_DoNotShareCacheAcrossContexts() {
            var (mockLdapUtils, gpLink, linkDn) = CreateContextTestData();
            using var firstContext = new GPOLocalGroupProcessorContext();
            using var secondContext = new GPOLocalGroupProcessorContext();

            await Task.WhenAll(
                firstContext.CreateGPOLocalGroupProcessor(mockLdapUtils.Object)
                    .ReadGPOLocalGroups(gpLink, "DC=TEST,DC=LOCAL"),
                secondContext.CreateGPOLocalGroupProcessor(mockLdapUtils.Object)
                    .ReadGPOLocalGroups(gpLink, "DC=TEST,DC=LOCAL"));

            mockLdapUtils.Verify(x => x.Query(
                It.Is<LdapQueryParameters>(parameters =>
                    parameters.LDAPFilter == new LdapFilter().AddAllObjects().GetFilter() &&
                    parameters.SearchBase == linkDn),
                It.IsAny<CancellationToken>()), Times.Exactly(2));
        }

        [Fact]
        public async Task GPOLocalGroupProcessorContext_QueryFailure_IsRetried() {
            var (mockLdapUtils, gpLink, linkDn) = CreateContextTestData();
            mockLdapUtils.SetupSequence(x => x.Query(
                    It.Is<LdapQueryParameters>(parameters =>
                        parameters.LDAPFilter == new LdapFilter().AddAllObjects().GetFilter()),
                    It.IsAny<CancellationToken>()))
                .Returns(new[] { LdapResult<IDirectoryObject>.Fail() }.ToAsyncEnumerable)
                .Returns(new[] { LdapResult<IDirectoryObject>.Ok(new Mock<IDirectoryObject>().Object) }
                    .ToAsyncEnumerable);
            using var context = new GPOLocalGroupProcessorContext();
            var processor = context.CreateGPOLocalGroupProcessor(mockLdapUtils.Object);

            await processor.ReadGPOLocalGroups(gpLink, "DC=TEST,DC=LOCAL");
            await processor.ReadGPOLocalGroups(gpLink, "DC=TEST,DC=LOCAL");

            mockLdapUtils.Verify(x => x.Query(
                It.Is<LdapQueryParameters>(parameters =>
                    parameters.LDAPFilter == new LdapFilter().AddAllObjects().GetFilter() &&
                    parameters.SearchBase == linkDn),
                It.IsAny<CancellationToken>()), Times.Exactly(2));
        }

        [Fact]
        public void GPOLocalGroupProcessorContext_CreateProcessor_AfterDispose_Throws() {
            var context = new GPOLocalGroupProcessorContext();
            context.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                context.CreateGPOLocalGroupProcessor(new MockLdapUtils()));
        }

        [Fact]
        public async Task GPOLocalGroupProcessorContext_Processor_AfterDispose_Throws() {
            var (mockLdapUtils, gpLink, _) = CreateContextTestData();
            var context = new GPOLocalGroupProcessorContext();
            var processor = context.CreateGPOLocalGroupProcessor(mockLdapUtils.Object);
            context.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                processor.ReadGPOLocalGroups(gpLink, "DC=TEST,DC=LOCAL"));
        }

        [Fact]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_Null_GPLink() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var result = await processor.ReadGPOLocalGroups(null, null);
            Assert.NotNull(result);
            Assert.Empty(result.AffectedComputers);
            Assert.Empty(result.DcomUsers);
            Assert.Empty(result.RemoteDesktopUsers);
            Assert.Empty(result.LocalAdmins);
            Assert.Empty(result.PSRemoteUsers);
        }

        [Fact]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_AffectedComputers_0() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            mockLDAPUtils.Setup(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>()))
                .Returns(Array.Empty<LdapResult<IDirectoryObject>>().ToAsyncEnumerable);
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var result = await processor.ReadGPOLocalGroups("teapot", null);
            Assert.NotNull(result);
            Assert.Empty(result.AffectedComputers);
            Assert.Empty(result.DcomUsers);
            Assert.Empty(result.RemoteDesktopUsers);
            Assert.Empty(result.LocalAdmins);
            Assert.Empty(result.PSRemoteUsers);
        }

        [Fact]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_Null_Gpcfilesyspath() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            var mockSearchResultEntry = new Mock<IDirectoryObject>();
            var sid = "teapot";
            mockSearchResultEntry.Setup(x => x.TryGetSecurityIdentifier(out sid)).Returns(true);
            var mockResult = LdapResult<IDirectoryObject>.Ok(mockSearchResultEntry.Object);
            var mockSearchResults = new List<LdapResult<IDirectoryObject>> { mockResult };
            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddComputersNoMSAs().GetFilter()) &&
                        y.Attributes.Equals(CommonProperties.ObjectSID)),
                    It.IsAny<CancellationToken>())).Returns(mockSearchResults.ToAsyncEnumerable);

            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddAllObjects().GetFilter())),
                    It.IsAny<CancellationToken>()))
                .Returns(Array.Empty<LdapResult<IDirectoryObject>>().ToAsyncEnumerable);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somedomain;0;][LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=someotherdomain;2;]";
            var result = await processor.ReadGPOLocalGroups(testGPLinkProperty, "DC=Testlab,DC=Local");

            Assert.Single(result.AffectedComputers);
            var actual = result.AffectedComputers.First();
            Assert.Equal(Label.Computer, actual.ObjectType);
            Assert.Equal("teapot", actual.ObjectIdentifier);
        }

        [Fact]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups_Does_Not_Skip_Enabled_And_Skips_Disabled_GPOs() {
            // Setup
            var mockLDAPUtils = new Mock<ILdapUtils>(MockBehavior.Loose);
            var gpcFileSysPath = Path.GetTempPath();

            var groupsXmlPath = Path.Join(gpcFileSysPath, "MACHINE", "Preferences", "Groups", "Groups.xml");
            Directory.CreateDirectory(Path.GetDirectoryName(groupsXmlPath));
            await File.WriteAllTextAsync(groupsXmlPath, GroupXmlContent);
            
            var gptTmplPath = Path.Join(gpcFileSysPath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");
            Directory.CreateDirectory(Path.GetDirectoryName(gptTmplPath));
            await File.WriteAllTextAsync(gptTmplPath, GpttmplInfContent); 
            
            var mockComputerEntry = new Mock<IDirectoryObject>();
            var mockSearchResultEntry = new Mock<IDirectoryObject>();
            var sid = "teapot";
            mockSearchResultEntry.Setup(x => x.TryGetSecurityIdentifier(out sid)).Returns(true);
            var mockResult = LdapResult<IDirectoryObject>.Ok(mockSearchResultEntry.Object);
            var mockSearchResults = new List<LdapResult<IDirectoryObject>> { mockResult };
            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddComputersNoMSAs().GetFilter()) &&
                        y.Attributes.Equals(CommonProperties.ObjectSID)),
                    It.IsAny<CancellationToken>())).Returns(mockSearchResults.ToAsyncEnumerable);
            mockComputerEntry.Setup(x => x.TryGetSecurityIdentifier(out sid)).Returns(true);
            mockLDAPUtils.Setup(x => x.ResolveAccountName(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal("S-1-5-21-3130019616-2776909439-2417379446-513", Label.User)));
            
            // Enabled
            var mockDirectory0 = new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, "",
                "ECAD920E-8EB1-4E31-A80E-DD36367F81F4");
            mockDirectory0.Properties = new Dictionary<string, string>() {
                { LDAPProperties.GPCFileSYSPath, gpcFileSysPath },
                { LDAPProperties.Flags, "0"}
            };
            var result0 = new List<LdapResult<IDirectoryObject>> {
                LdapResult<IDirectoryObject>.Ok(mockDirectory0),
            };
            // User Configuration Disabled
            var mockDirectory1 = new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, "",
                "ECAD920E-8EB1-4E31-A80E-DD36367F81F4");
            mockDirectory1.Properties = new Dictionary<string, string>() {
                { LDAPProperties.GPCFileSYSPath, gpcFileSysPath },
                { LDAPProperties.Flags, "1"}
            };
            var result1 = new List<LdapResult<IDirectoryObject>> {
                LdapResult<IDirectoryObject>.Ok(mockDirectory1),
            };
            // Computer Configuration Disabled -- Skipped
            var mockDirectory2 = new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, "",
                "ECAD920E-8EB1-4E31-A80E-DD36367F81F4");
            mockDirectory2.Properties = new Dictionary<string, string>() {
                { LDAPProperties.GPCFileSYSPath, gpcFileSysPath },
                { LDAPProperties.Flags, "2"}
            };
            var result2 = new List<LdapResult<IDirectoryObject>> {
                LdapResult<IDirectoryObject>.Ok(mockDirectory2),
            };
            // Disabled -- Skipped
            var mockDirectory3 = new MockDirectoryObject("CN=Users,DC=testlab,DC=local", null, "",
                "ECAD920E-8EB1-4E31-A80E-DD36367F81F4");
            mockDirectory3.Properties = new Dictionary<string, string>() {
                { LDAPProperties.GPCFileSYSPath, gpcFileSysPath },
                { LDAPProperties.Flags, "3"}
            };
            var result3 = new List<LdapResult<IDirectoryObject>> {
                LdapResult<IDirectoryObject>.Ok(mockDirectory3),
            };
            
            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddAllObjects().GetFilter()) &&
                        y.SearchScope.Equals(SearchScope.Base) &&
                        y.Attributes.Contains(LDAPProperties.GPCFileSYSPath) &&
                        y.Attributes.Contains(LDAPProperties.Flags) &&
                        y.SearchBase.Equals("cn=foouser (blah)123/dc=somedomain", StringComparison.OrdinalIgnoreCase) &&
                        y.DomainName.Equals("somedomain", StringComparison.OrdinalIgnoreCase)),
                    It.IsAny<CancellationToken>()))
                .Returns(result0.ToAsyncEnumerable);
            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddAllObjects().GetFilter()) &&
                        y.SearchScope.Equals(SearchScope.Base) &&
                        y.Attributes.Contains(LDAPProperties.GPCFileSYSPath) &&
                        y.Attributes.Contains(LDAPProperties.Flags) &&
                        y.SearchBase.Equals("cn=foouser (blah)123/dc=someotherdomain", StringComparison.OrdinalIgnoreCase) &&
                        y.DomainName.Equals("someotherdomain", StringComparison.OrdinalIgnoreCase)),
                    It.IsAny<CancellationToken>()))
                .Returns(result1.ToAsyncEnumerable);
            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddAllObjects().GetFilter()) &&
                        y.SearchScope.Equals(SearchScope.Base) &&
                        y.Attributes.Contains(LDAPProperties.GPCFileSYSPath) &&
                        y.Attributes.Contains(LDAPProperties.Flags) &&
                        y.SearchBase.Equals("cn=foouser (blah)123/dc=somethirddomain", StringComparison.OrdinalIgnoreCase) &&
                        y.DomainName.Equals("somethirddomain", StringComparison.OrdinalIgnoreCase)),
                    It.IsAny<CancellationToken>()))
                .Returns(result2.ToAsyncEnumerable);
            mockLDAPUtils
                .Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(y =>
                        y.LDAPFilter.Equals(new LdapFilter().AddAllObjects().GetFilter()) &&
                        y.SearchScope.Equals(SearchScope.Base) &&
                        y.Attributes.Contains(LDAPProperties.GPCFileSYSPath) &&
                        y.Attributes.Contains(LDAPProperties.Flags) &&
                        y.SearchBase.Equals("cn=foouser (blah)123/dc=somefourthdomain", StringComparison.OrdinalIgnoreCase) &&
                        y.DomainName.Equals("somefourthdomain", StringComparison.OrdinalIgnoreCase)),
                    It.IsAny<CancellationToken>()))
                .Returns(result3.ToAsyncEnumerable);
            
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            var testGPLinkProperty0 = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somedomain;0;]";
            var testGPLinkProperty1 = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=someotherdomain;0;]";
            var testGPLinkProperty2 = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somethirddomain;0;]";
            var testGPLinkProperty3 = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somefourthdomain;0;]";
            
            // Act
            var act0 = await processor.ReadGPOLocalGroups(testGPLinkProperty0, "DC=Testlab,DC=Local");
            var act1 = await processor.ReadGPOLocalGroups(testGPLinkProperty1, "DC=Testlab,DC=Local");
            var act2 = await processor.ReadGPOLocalGroups(testGPLinkProperty2, "DC=Testlab,DC=Local");
            var act3 = await processor.ReadGPOLocalGroups(testGPLinkProperty3, "DC=Testlab,DC=Local");
            
            // Assert
            Assert.Single(act0.AffectedComputers);
            Assert.Single(act1.AffectedComputers);
            Assert.Single(act2.AffectedComputers);
            Assert.Single(act3.AffectedComputers);
            
            Assert.Single(act0.LocalAdmins);
            Assert.Single(act1.LocalAdmins);
            Assert.Empty(act2.LocalAdmins);
            Assert.Empty(act3.LocalAdmins);
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task GPOLocalGroupProcessor_ReadGPOLocalGroups() {
            var mockLDAPUtils = new Mock<ILdapUtils>(MockBehavior.Loose);
            var gpcFileSysPath = Path.GetTempPath();

            var groupsXmlPath = Path.Join(gpcFileSysPath, "MACHINE", "Preferences", "Groups", "Groups.xml");

            Path.GetDirectoryName(groupsXmlPath);
            Directory.CreateDirectory(Path.GetDirectoryName(groupsXmlPath));
            File.WriteAllText(groupsXmlPath, GroupXmlContent);

            var mockComputerEntry = new Mock<IDirectoryObject>();
            var sid = "teapot";
            mockComputerEntry.Setup(x => x.TryGetSecurityIdentifier(out sid)).Returns(true);
            var mockComputerResults = new List<LdapResult<IDirectoryObject>>();
            mockComputerResults.Add(LdapResult<IDirectoryObject>.Ok(mockComputerEntry.Object));

            var mockGCPFileSysPathEntry = new Mock<IDirectoryObject>();
            mockGCPFileSysPathEntry.Setup(x => x.TryGetProperty(It.IsAny<string>(), out gpcFileSysPath)).Returns(true);
            var mockGCPFileSysPathResults = new List<LdapResult<IDirectoryObject>>
                { LdapResult<IDirectoryObject>.Ok(mockGCPFileSysPathEntry.Object) };

            mockLDAPUtils.SetupSequence(x => x.Query(It.IsAny<LdapQueryParameters>(), It.IsAny<CancellationToken>()))
                .Returns(mockComputerResults.ToAsyncEnumerable)
                .Returns(mockGCPFileSysPathResults.ToAsyncEnumerable)
                .Returns(Array.Empty<LdapResult<IDirectoryObject>>().ToAsyncEnumerable);
            var domain = MockableDomain.Construct("TESTLAB.LOCAL");
            mockLDAPUtils.Setup(x => x.GetDomain(out domain)).Returns(true);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            

            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=somedomain;0;][LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123/dc=someotherdomain;2;]";
            var result = await processor.ReadGPOLocalGroups(testGPLinkProperty, null);
            
            //mockLDAPUtils.VerifyAll();
            Assert.Single(result.AffectedComputers);
            var actual = result.AffectedComputers.First();
            Assert.Equal(Label.Computer, actual.ObjectType);
            Assert.Equal("teapot", actual.ObjectIdentifier);
        }

        [Fact]
        public async Task GPOLocalGroupProcess_ProcessGPOXMLFile_NoFile() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            var gpcFileSysPath = Path.Join(Path.GetTempPath(), "made", "up", "path");

            var actual = await processor.ProcessGPOXmlFile(gpcFileSysPath, "somedomain").ToArrayAsync();
            Assert.NotNull(actual);
            Assert.Empty(actual);
        }

        private static (Mock<ILdapUtils> LdapUtils, string GPLink, string LinkDn) CreateContextTestData() {
            var mockLdapUtils = new Mock<ILdapUtils>();
            var computerEntry = new Mock<IDirectoryObject>();
            var computerSid = $"S-1-5-21-{Random.Shared.Next()}-{Random.Shared.Next()}-{Random.Shared.Next()}-1000";
            computerEntry.Setup(x => x.TryGetSecurityIdentifier(out computerSid)).Returns(true);
            var computerResults = new[] { LdapResult<IDirectoryObject>.Ok(computerEntry.Object) };
            var gpoResults = new[] { LdapResult<IDirectoryObject>.Ok(new Mock<IDirectoryObject>().Object) };

            mockLdapUtils.Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(parameters =>
                        parameters.LDAPFilter == new LdapFilter().AddComputersNoMSAs().GetFilter()),
                    It.IsAny<CancellationToken>()))
                .Returns(computerResults.ToAsyncEnumerable);
            mockLdapUtils.Setup(x => x.Query(
                    It.Is<LdapQueryParameters>(parameters =>
                        parameters.LDAPFilter == new LdapFilter().AddAllObjects().GetFilter()),
                    It.IsAny<CancellationToken>()))
                .Returns(gpoResults.ToAsyncEnumerable);

            var linkDn = $"CN={Guid.NewGuid():N},CN=Policies,CN=System,DC=TEST,DC=LOCAL";
            return (mockLdapUtils, $"[LDAP://{linkDn};0]", linkDn);
        }

        [Fact]
        public async Task GPOLocalGroupProcess_ProcessGPOXMLFile_Disabled() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            var gpcFileSysPath = Path.GetTempPath();
            var groupsXmlPath = Path.Join(gpcFileSysPath, "MACHINE", "Preferences", "Groups", "Groups.xml");

            Directory.CreateDirectory(Path.GetDirectoryName(groupsXmlPath));
            File.WriteAllText(groupsXmlPath, GroupXmlContentDisabled);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var actual = await processor.ProcessGPOXmlFile(gpcFileSysPath, "somedomain").ToArrayAsync();
            Assert.NotNull(actual);
            Assert.Empty(actual);
        }

        [Fact]
        public async Task GPOLocalGroupProcessor_ProcessGPOXMLFile() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            mockLDAPUtils.Setup(x => x.ResolveAccountName(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal("S-1-5-21-3130019616-2776909439-2417379446-513", Label.User)));
            var gpcFileSysPath = Path.GetTempPath();
            var groupsXmlPath = Path.Join(gpcFileSysPath, "MACHINE", "Preferences", "Groups", "Groups.xml");

            Directory.CreateDirectory(Path.GetDirectoryName(groupsXmlPath));
            File.WriteAllText(groupsXmlPath, GroupXmlContent);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            var actual = await processor.ProcessGPOXmlFile(gpcFileSysPath, "somedomain").ToArrayAsync();

            Assert.NotNull(actual);
            Assert.NotEmpty(actual);
        }

        [Fact]
        public async Task GPOLocalGroupProcess_ProcessGPOTemplateFile_NoFile() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);
            var gpcFileSysPath = Path.Join(Path.GetTempPath(), "made", "up", "path");

            var actual = await processor.ProcessGPOTemplateFile(gpcFileSysPath, "somedomain").ToListAsync();
            Assert.NotNull(actual);
            Assert.Empty(actual);
        }

        [Fact]
        public async Task GPOLocalGroupProcess_ProcessGPOTemplateFile_NoMatch() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            var gpcFileSysPath = Path.GetTempPath();
            var gptTmplPath = Path.Join(gpcFileSysPath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");

            Directory.CreateDirectory(Path.GetDirectoryName(gptTmplPath));
            File.WriteAllText(gptTmplPath, GpttmplInfContentNoMatch);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var actual = await processor.ProcessGPOTemplateFile(gpcFileSysPath, "somedomain").ToListAsync();
            Assert.NotNull(actual);
            Assert.Empty(actual);
        }

        [Fact]
        public async Task GPOLocalGroupProcess_ProcessGPOTemplateFile_NullSID() {
            var mockLDAPUtils = new MockLdapUtils();
            var gpcFileSysPath = Path.GetTempPath();
            var gptTmplPath = Path.Join(gpcFileSysPath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");

            Directory.CreateDirectory(Path.GetDirectoryName(gptTmplPath));
            File.WriteAllText(gptTmplPath, GpttmplInfContent);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils);

            var actual = await processor.ProcessGPOTemplateFile(gpcFileSysPath, "somedomain").ToListAsync();
            Assert.NotNull(actual);
            Assert.NotEmpty(actual);
        }

        [Fact]
        public async Task GPOLocalGroupProcess_ProcessGPOTemplateFile() {
            var mockLDAPUtils = new Mock<ILdapUtils>();
            mockLDAPUtils.Setup(x => x.ResolveAccountName(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((true, new TypedPrincipal("S-1-5-21-3130019616-2776909439-2417379446-513", Label.User)));
            var gpcFileSysPath = Path.GetTempPath();
            var gptTmplPath = Path.Join(gpcFileSysPath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");

            Directory.CreateDirectory(Path.GetDirectoryName(gptTmplPath));
            File.WriteAllText(gptTmplPath, GpttmplInfContent);

            var processor = new GPOLocalGroupProcessor(mockLDAPUtils.Object);

            var actual = await processor.ProcessGPOTemplateFile(gpcFileSysPath, "somedomain").ToListAsync();
            Assert.NotNull(actual);
            Assert.NotEmpty(actual);
            var expected = new GPOLocalGroupProcessor.GroupAction() {
                Action = GPOLocalGroupProcessor.GroupActionOperation.Add,
                Target = GPOLocalGroupProcessor.GroupActionTarget.RestrictedMember,
                TargetSid = "S-1-5-21-3130019616-2776909439-2417379446-513",
                TargetRid = GPOLocalGroupProcessor.LocalGroupRids.Administrators,
                TargetType = Label.User
            };
            Assert.Contains(expected, actual);
        }

        [Fact]
        public void GPOLocalGroupProcess_GroupAction() {
            var ga = new GPOLocalGroupProcessor.GroupAction();
            var tp = ga.ToTypedPrincipal();
            var str = ga.ToString();

            Assert.NotNull(tp);
            Assert.Equal(new TypedPrincipal(), tp);
            Assert.NotNull(str);
            Assert.Equal("Action: Add, Target: RestrictedMemberOf, TargetSid: , TargetType: Base, TargetRid: None",
                str);
        }
    }
}

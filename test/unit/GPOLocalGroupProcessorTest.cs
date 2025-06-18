using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
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
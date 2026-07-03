using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;

namespace CommonLibTest
{
    public class SPNProcessorsTest
    {
        [Fact]
        public async Task ReadSPNTargets_SPNLengthZero_YieldBreak()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            var servicePrincipalNames = Array.Empty<string>();
            const string distinguishedName = "cn=policies,cn=system,DC=testlab,DC=local";
            await foreach (var spn in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
                Assert.Null(spn);
        }

        [Fact]
        public async Task ReadSPNTargets_NoPortSupplied_ParsedCorrectly()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            string[] servicePrincipalNames = {"MSSQLSvc/PRIMARY.TESTLAB.LOCAL"};
            const string distinguishedName = "cn=policies,cn=system,DC=testlab,DC=local";

            var expected = new SPNPrivilege
            {
                ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 1433,
                Service = EdgeNames.SQLAdmin
            };

            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
            }
        }

        [Fact]
        public async Task ReadSPNTargets_BadPortSupplied_ParsedCorrectly()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            string[] servicePrincipalNames = {"MSSQLSvc/PRIMARY.TESTLAB.LOCAL:abcd"};
            const string distinguishedName = "cn=policies,cn=system,DC=testlab,DC=local";

            var expected = new SPNPrivilege
            {
                ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 1433,
                Service = EdgeNames.SQLAdmin
            };

            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
            }
        }

        [Fact]
        public async Task ReadSPNTargets_SuppliedPort_ParsedCorrectly()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            string[] servicePrincipalNames = {"MSSQLSvc/PRIMARY.TESTLAB.LOCAL:2345"};
            const string distinguishedName = "cn=policies,cn=system,DC=testlab,DC=local";

            var expected = new SPNPrivilege
            {
                ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 2345,
                Service = EdgeNames.SQLAdmin
            };

            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
            }
        }

        [Fact]
        public async Task ReadSPNTargets_MissingMssqlSvc_NotRead()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            string[] servicePrincipalNames = {"myhost.redmond.microsoft.com:1433"};
            const string distinguishedName = "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM";
            await foreach (var spn in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
                Assert.Null(spn);
        }

        [Fact]
        public async Task ReadSPNTargets_SPNWithAddressSign_NotRead()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            string[] servicePrincipalNames = {"MSSQLSvc/myhost.redmond.microsoft.com:1433 user@domain"};
            const string distinguishedName = "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM";
            await foreach (var spn in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
                Assert.Null(spn);
        }
        
        [Fact]
        public async Task ReadSPNTargets_SendComputerStatus()
        {
            var processor = new SPNProcessors(new MockLdapUtils());
            string[] servicePrincipalNames = {"MSSQLSvc/PRIMARY.TESTLAB.LOCAL:2345"};
            const string distinguishedName = "cn=policies,cn=system,DC=testlab,DC=local";
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += status => 
            {
                receivedStatus.Add(status); 
                return Task.CompletedTask;
            };

            var expected = new SPNPrivilege
            {
                ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1001", Port = 2345,
                Service = EdgeNames.SQLAdmin
            };

            var count = 0;
            await foreach (var actual in processor.ReadSPNTargets(servicePrincipalNames, distinguishedName))
            {
                Assert.Equal(expected.ComputerSID, actual.ComputerSID);
                Assert.Equal(expected.Port, actual.Port);
                Assert.Equal(expected.Service, actual.Service);
                count += 1;
            }
            Assert.NotEmpty(receivedStatus);
            Assert.Equal(count, receivedStatus.Count);
        }
    }
}
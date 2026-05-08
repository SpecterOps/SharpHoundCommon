using System;
using System.Collections.Generic;
using System.Linq;
using SharpHoundCommonLib.LDAPQueries;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LDAPFilterTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LDAPFilterTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            // This runs once per test.
        }

        public void Dispose()
        {
        }

        #region Creation

        [Fact]
        public void LDAPFilter_CreateNewFilter_FilterNotNull()
        {
            var test = new LdapFilter();
            Assert.NotNull(test);
        }

        #endregion

        #region Behavioral

        [Fact]
        public void LDAPFilter_GroupFilter_FilterCorrect()
        {
            var test = new LdapFilter();
            test.AddGroups();
            var filter = test.GetFilter();
            _testOutputHelper.WriteLine(filter);
            Assert.Equal(
                "(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))",
                filter);
        }

        [Fact]
        public void LDAPFilter_GroupFilter_ExtraFilter_FilterCorrect()
        {
            var test = new LdapFilter();
            test.AddGroups("objectclass=*");
            var filter = test.GetFilter();
            _testOutputHelper.WriteLine(filter);
            Assert.Equal(
                "(&(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))(objectclass=*))",
                filter);
        }

        [Fact]
        public void LDAPFilter_GetFilterList()
        {
            var test = new LdapFilter().AddUsers().AddComputers();
            IEnumerable<string> filters = test.GetFilterList();

            int i = 0;
            string userFilter = "(|(samaccounttype=805306368)(samaccounttype=805306370))";
            string computerFilter = "(samaccounttype=805306369)";
            string[] expected = {userFilter, computerFilter};

            foreach (var filter in filters) {
                 Assert.Equal(expected[i], filter);
                 i++;
            }
        }

        [Fact]
        public void LDAPFilter_GetFilterList_MergeFilter()
        {
            var test = new LdapFilter();
            test.AddUsers();
            test.AddComputers();
            string mandatoryFilter1 = "(objectclass=*)";
            string mandatoryFilter2 = "(iamamandatoryfilter=1)";
            test.AddFilter(mandatoryFilter1, true);
            test.AddFilter(mandatoryFilter2, true);

            IEnumerable<string> filters = test.GetFilterList();

            string computerFilter = "(samaccounttype=805306369)";
            string userFilter = "(|(samaccounttype=805306368)(samaccounttype=805306370))";

            // Check that each filter includes all mandatory filters
            foreach (var filter in filters)
            {
                Assert.StartsWith("(&", filter);
                Assert.Contains(mandatoryFilter1, filter);
                Assert.Contains(mandatoryFilter2, filter);
            }

            // Check that each of userFilter and computerFilter are accounted for
            Assert.Single(filters, f => f.Contains(userFilter));
            Assert.Single(filters, f => f.Contains(computerFilter));

            Assert.Equal(2, filters.Count());
        }

        #endregion
    }
}
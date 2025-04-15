using System;
using System.Collections.Generic;
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

        #endregion
    }
}
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using Xunit;

public class LdapConnectionPoolTest
{
    [Fact]
    public async Task LdapConnectionPool_Static_GetDomain_Add_To_ExcludedDomains_ShouldExitEarly()
    {
        var mockLogger = new Mock<ILogger>();
        var ldapConfig = new LdapConfig();
        var connectionPool = new ConnectionPoolManager(ldapConfig, mockLogger.Object);

        var connectAttempt = await connectionPool.TestDomainConnection("excludedDomain.com", false);

        Assert.False(connectAttempt.Success);
        Assert.Contains("excluded for connection attempt", connectAttempt.Message);
    }
}
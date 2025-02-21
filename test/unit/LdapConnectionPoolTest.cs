using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using Xunit;

public class LdapConnectionPoolTest
{
    private static void AddExclusionDomain(string identifier) {
        var excludedDomainsField = typeof(LdapConnectionPool)
            .GetField("_excludedDomains", BindingFlags.Static | BindingFlags.NonPublic);

        var excludedDomains = (ConcurrentHashSet)excludedDomainsField.GetValue(null);

        excludedDomains.Add(identifier);
    }

    [Fact]
    public async Task LdapConnectionPool_ExcludedDomains_ShouldExitEarly()
    {
        var mockLogger = new Mock<ILogger>();
        var ldapConfig = new LdapConfig();
        var connectionPool = new ConnectionPoolManager(ldapConfig, mockLogger.Object);

        AddExclusionDomain("excludedDomain.com");
        var connectAttempt = await connectionPool.TestDomainConnection("excludedDomain.com", false);

        Assert.False(connectAttempt.Success);
        Assert.Contains("excluded for connection attempt", connectAttempt.Message);
    }

    [Fact]
    public async Task LdapConnectionPool_ExcludedDomains_NonExcludedShouldntExit()
    {
        var mockLogger = new Mock<ILogger>();
        var ldapConfig = new LdapConfig();
        var connectionPool = new ConnectionPoolManager(ldapConfig, mockLogger.Object);

        AddExclusionDomain("excludedDomain.com");
        var connectAttempt = await connectionPool.TestDomainConnection("perfectlyValidDomain.com", false);

        Assert.DoesNotContain("excluded for connection attempt", connectAttempt.Message);
    }
}
using System;
using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using Xunit;

public class LdapConnectionPoolTest : IDisposable
{
    public void Dispose() {
        ResetExclusionDomain();
    }

    private static void AddExclusionDomain(string identifier) {
        var excludedDomainsField = typeof(LdapConnectionPool)
            .GetField("ExcludedDomains", BindingFlags.Static | BindingFlags.NonPublic);

        var excludedDomains = (ConcurrentHashSet)excludedDomainsField.GetValue(null);

        excludedDomains.Add(identifier);
    }

    private static void ResetExclusionDomain() {
        var excludedDomainsField = typeof(LdapConnectionPool)
            .GetField("ExcludedDomains", BindingFlags.Static | BindingFlags.NonPublic);

        var excludedDomains = (ConcurrentHashSet)excludedDomainsField.GetValue(null);

        excludedDomains.Clear();
    }

    private static ConcurrentBag<LdapConnectionWrapper> GetConnectionsBag(LdapConnectionPool pool) {
        var field = typeof(LdapConnectionPool)
            .GetField("_connections", BindingFlags.Instance | BindingFlags.NonPublic);
        return (ConcurrentBag<LdapConnectionWrapper>)field.GetValue(pool);
    }
 
    private static ConcurrentBag<LdapConnectionWrapper> GetGlobalCatalogConnectionsBag(LdapConnectionPool pool) {
        var field = typeof(LdapConnectionPool)
            .GetField("_globalCatalogConnection", BindingFlags.Instance | BindingFlags.NonPublic);
        return (ConcurrentBag<LdapConnectionWrapper>)field.GetValue(pool);
    }

    [Fact]
    public async Task LdapConnectionPool_ExcludedDomains_ShouldExitEarly()
    {
        ResetExclusionDomain();
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
        ResetExclusionDomain();
        var mockLogger = new Mock<ILogger>();
        var ldapConfig = new LdapConfig();
        var connectionPool = new ConnectionPoolManager(ldapConfig, mockLogger.Object);

        AddExclusionDomain("excludedDomain.com");
        var connectAttempt = await connectionPool.TestDomainConnection("perfectlyValidDomain.com", false);

        Assert.DoesNotContain("excluded for connection attempt", connectAttempt.Message);
    }

    /// <summary>
    /// Fix: GetGlobalCatalogConnectionAsync was missing the excluded-domain early-exit check.
    /// Verifies that a domain in the exclusion list is rejected even for global catalog connections.
    /// </summary>
    [Fact]
    public async Task LdapConnectionPool_ExcludedDomains_GlobalCatalog_ShouldExitEarly()
    {
        ResetExclusionDomain();
        var mockLogger = new Mock<ILogger>();
        var ldapConfig = new LdapConfig();
        var connectionPool = new ConnectionPoolManager(ldapConfig, mockLogger.Object);

        AddExclusionDomain("excludedGcDomain.com");
        var connectAttempt = await connectionPool.TestDomainConnection("excludedGcDomain.com", true);

        Assert.False(connectAttempt.Success);
        Assert.Contains("excluded for connection attempt", connectAttempt.Message);
    }

    /// <summary>
    /// Fix: Dispose() previously only drained the regular connection bag; the global-catalog
    /// bag was left untouched, leaking those connections.
    /// Verifies that Dispose() empties the global-catalog connection bag.
    /// </summary>
    [Fact]
    public void LdapConnectionPool_Dispose_ShouldDisposeGlobalCatalogConnections()
    {
        var ldapConfig = new LdapConfig();
        var pool = new LdapConnectionPool("gc-dispose-test.local", "gc-dispose-test.local", ldapConfig);

        var gcBag = GetGlobalCatalogConnectionsBag(pool);

        // Inject a real (but unconnected) LdapConnection into the GC bag.
        var ldapId = new LdapDirectoryIdentifier("localhost", 3268, false, false);
        var conn = new LdapConnection(ldapId);
        var wrapper = new LdapConnectionWrapper(conn, null, true, "gc-dispose-test.local");
        gcBag.Add(wrapper);

        Assert.False(gcBag.IsEmpty);

        pool.Dispose();

        // After Dispose the bag must be drained.
        Assert.True(gcBag.IsEmpty);
    }

    /// <summary>
    /// Verifies that ReleaseConnection routes a GlobalCatalog wrapper to the GC bag,
    /// not the regular connections bag.
    /// </summary>
    [Fact]
    public void LdapConnectionPool_ReleaseConnection_GlobalCatalog_RoutesToGCBag()
    {
        var ldapConfig = new LdapConfig();
        var pool = new LdapConnectionPool("release-gc-test.local", "release-gc-test.local", ldapConfig);

        var connectionsBag = GetConnectionsBag(pool);
        var gcBag = GetGlobalCatalogConnectionsBag(pool);

        var ldapId = new LdapDirectoryIdentifier("localhost", 3268, false, false);
        var conn = new LdapConnection(ldapId);
        var gcWrapper = new LdapConnectionWrapper(conn, null, true, "release-gc-test.local");

        pool.ReleaseConnection(gcWrapper);

        Assert.Single(gcBag);
        Assert.Empty(connectionsBag);

        pool.Dispose();
    }

    /// <summary>
    /// Verifies that ReleaseConnection routes a non-GlobalCatalog wrapper to the regular
    /// connections bag, not the GC bag.
    /// </summary>
    [Fact]
    public void LdapConnectionPool_ReleaseConnection_NonGlobalCatalog_RoutesToConnectionsBag()
    {
        var ldapConfig = new LdapConfig();
        var pool = new LdapConnectionPool("release-regular-test.local", "release-regular-test.local", ldapConfig);

        var connectionsBag = GetConnectionsBag(pool);
        var gcBag = GetGlobalCatalogConnectionsBag(pool);

        var ldapId = new LdapDirectoryIdentifier("localhost", 389, false, false);
        var conn = new LdapConnection(ldapId);
        var wrapper = new LdapConnectionWrapper(conn, null, false, "release-regular-test.local");

        pool.ReleaseConnection(wrapper);

        Assert.Single(connectionsBag);
        Assert.Empty(gcBag);

        pool.Dispose();
    }
}

using System;
using System.Reflection;
using CommonLibTest.CollectionDefinitons;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using Xunit;

namespace CommonLibTest;

[Collection(nameof(CacheTestCollectionDefinition))]
public class CommonLibTests
{

    public CommonLibTests()
    {
        ResetCommonLibState();
    }
    
    [Fact]
    public void InitializeCommonLib_FirstCallWithoutCache_CreatesAndSetsCacheInstance()
    {
        // Arrange & Act
        CommonLib.InitializeCommonLib();

        // Assert
        var cache = Cache.GetCacheInstance();
        Assert.NotNull(cache);
        Assert.NotNull(cache.IdToTypeCache);
        Assert.NotNull(cache.ValueToIdCache);
        Assert.NotNull(cache.GlobalCatalogCache);
        Assert.NotNull(cache.MachineSidCache);
        Assert.NotNull(cache.SIDToDomainCache);
    }

    [Fact]
    public void InitializeCommonLib_UsesProvidedInstance()
    {
        // Arrange
        var provided = Cache.CreateNewCache();

        // Act
        CommonLib.InitializeCommonLib(cache: provided);

        // Assert
        Assert.Same(provided, Cache.GetCacheInstance());
    }

    [Fact]
    public void InitializeCommonLib_2Calls_LogsWarningAndDoesNotReplaceCache()
    {
        // Arrange
        var cache1 = Cache.CreateNewCache();
        CommonLib.InitializeCommonLib(cache: cache1);

        var cache2 = Cache.CreateNewCache();
        var logger = new Mock<ILogger>();

        // Act
        CommonLib.InitializeCommonLib(logger.Object, cache2);

        // Assert
        Assert.Same(cache1, Cache.GetCacheInstance()); // cache1 should be then one used since lib was already initialized

        logger.Verify(x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) =>
                    v.ToString() != null &&
                    v.ToString().Contains("already initialized", StringComparison.InvariantCultureIgnoreCase)),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once());
    }
    
    private static void ResetCommonLibState()
    {
        // Reset CommonLib._initialized (private static)
        var commonLibType = typeof(CommonLib);
        var initializedField = commonLibType.GetField("_initialized",
            BindingFlags.Static | BindingFlags.NonPublic);

        if (initializedField == null)
            throw new InvalidOperationException("CommonLib _initialized field not found");

        initializedField.SetValue(null, false);

        // Reset cache singleton so tests don't leak state into each other
        Cache.SetCacheInstance(null);
    }
}
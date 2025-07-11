using System;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest;

public class AdaptiveTimeoutTest {
    private readonly ITestOutputHelper _testOutputHelper;

    public AdaptiveTimeoutTest(ITestOutputHelper testOutputHelper) {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_NotEnoughSamplesAsync() {
        var maxTimeout = TimeSpan.FromSeconds(1);
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 10, 1000, 3);

        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50));

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_AdaptiveDisabled() {
        var maxTimeout = TimeSpan.FromSeconds(1);
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 10, 1000, 3, false);

        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50));
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50));
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50));

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout() {
        var maxTimeout = TimeSpan.FromSeconds(1);
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 10, 1000, 3);

        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(40));
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50));
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(60));

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.True(adaptiveTimeoutResult < maxTimeout);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_TimeSpikeSafetyValve() {
        var maxTimeout = TimeSpan.FromSeconds(1);
        var numSamples = 30;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 3);

        for (int i = 0; i < numSamples; i++)
            await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(10));

        for (int i = 0; i < 6; i++)
            await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(100));

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
    }
}
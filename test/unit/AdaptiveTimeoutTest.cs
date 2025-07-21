using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Exceptions;
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
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromSeconds(1);
        var numSamples = 30;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 10);

        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(10)));

        await Task.WhenAll(tasks);

        for (int i = 0; i < 3; i++)
            await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(200));

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_TimeSpikeSafetyValve_IgnoreHiccup() {
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromMilliseconds(100);
        var numSamples = 10;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 5);

        // Prepare our successful samples
        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(i)));

        await Task.WhenAll(tasks);

        // Add some timeout tasks that will resolve last
        for (int i = 0; i < 3; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(200)));

        // These tasks are added later but will resolve first
        for (int i = 0; i < 4; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(i)));

        await Task.WhenAll(tasks);
        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        // So our time spike safety valve should ignore the hiccup, since later tasks have resolved
        // by the time the safety valve has triggered by the timeout tasks
        Assert.True(adaptiveTimeoutResult < maxTimeout);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_ThrowWhenExcessiveTimeouts() {
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromMilliseconds(100);
        var numSamples = 10;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 5, throwIfExcessiveTimeouts: true);

        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(10)));

        await Task.WhenAll(tasks);

        for (int i = 0; i < 20; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(200)));

        await Assert.ThrowsAsync<ExcessiveTimeoutsException>(async () => await Task.WhenAll(tasks));
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_DoNotThrowWhenExcessiveTimeouts() {
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromMilliseconds(100);
        var numSamples = 10;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 5, throwIfExcessiveTimeouts: false);

        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(10)));

        await Task.WhenAll(tasks);

        for (int i = 0; i < 20; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(200)));

        await Task.WhenAll(tasks);
    }

    [Fact]
    public void AdaptiveTimeout_AtomicDecrementWithFloor_IsThreadSafe() {
        int value = 1000;
        int decrement = 1;
        int threads = 10;
        int decrementsPerThread = 100;

        Parallel.For(0, threads, i => {
            for (int j = 0; j < decrementsPerThread; j++) {
                AdaptiveTimeout.AtomicDecrementWithFloor(ref value, decrement, 0);
            }
        });

        Assert.Equal(1000 - threads * decrementsPerThread, value);
    }
}
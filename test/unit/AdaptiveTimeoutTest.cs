using System;
using System.Collections.Generic;
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
        var observedLatency= -50.0;

        var maxTimeout = TimeSpan.FromSeconds(1);
        var minTimeout = TimeSpan.Zero;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 10, 1000, 3);

        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50), latencyObservation: LatencyObservation);

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
        Assert.InRange(observedLatency, 0.0, 60);
        return;

        void LatencyObservation(double latency) {
            observedLatency = latency;
        }
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_AdaptiveDisabled() {
        var observedLatency1= -50.0;
        var observedLatency2= -50.0;
        var observedLatency3= -50.0;

        var maxTimeout = TimeSpan.FromSeconds(1);
        var minTimeout = TimeSpan.Zero;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 10, 1000, 3, false);

        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50), latencyObservation: LatencyObservation1);
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50), latencyObservation: LatencyObservation2);
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50), latencyObservation: LatencyObservation3);

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
        Assert.InRange(observedLatency1, 0.0, 60);
        Assert.InRange(observedLatency2, 0.0, 60);
        Assert.InRange(observedLatency3, 0.0, 60);
        return;


        void LatencyObservation1(double latency) {
            observedLatency1 = latency;
        }
        void LatencyObservation2(double latency) {
            observedLatency2 = latency;
        }
        void LatencyObservation3(double latency) {
            observedLatency3 = latency;
        }
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout() {
        var observedLatency1= -50.0;
        var observedLatency2= -50.0;
        var observedLatency3= -50.0;
        var maxTimeout = TimeSpan.FromSeconds(1);
        var minTimeout = TimeSpan.Zero;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 10, 1000, 3);

        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(40), latencyObservation: LatencyObservation1);
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(50), latencyObservation: LatencyObservation2);
        await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(60), latencyObservation: LatencyObservation3);

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.True(adaptiveTimeoutResult < maxTimeout);
        Assert.InRange(observedLatency1, 0.0, 55);
        Assert.InRange(observedLatency2, 0.0, 65);
        Assert.InRange(observedLatency3, 0.0, 75);
        return;
        
        void LatencyObservation1(double latency) {
            observedLatency1 = latency;
        }
        void LatencyObservation2(double latency) {
            observedLatency2 = latency;
        }
        void LatencyObservation3(double latency) {
            observedLatency3 = latency;
        }
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_TimeSpikeSafetyValve() {
        var observations = new List<double>();
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromSeconds(1);
        var minTimeout = TimeSpan.Zero;
        var numSamples = 30;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 10);

        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(10), latencyObservation: LatencyObservation));

        await Task.WhenAll(tasks);

        for (int i = 0; i < 3; i++)
            await adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(500), latencyObservation: LatencyObservation);

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(maxTimeout, adaptiveTimeoutResult);
        foreach (var t in observations) {
            Assert.InRange(t, 0.0, 1000.1);
        }
        return;
        
        void LatencyObservation(double latency) => observations.Add(latency);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_TimeSpikeSafetyValve_IgnoreHiccup() {
        var completedObservations = new List<double>();
        var timeoutObservations = new List<double>();
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromSeconds(1);
        var minTimeout = TimeSpan.Zero;
        var numSamples = 5;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 2);

        // Prepare our successful samples
        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout((_) => Task.CompletedTask, latencyObservation: LatencyCompletedObservation));

        await Task.WhenAll(tasks);

        // Add some timeout tasks that will resolve last
        for (int i = 0; i < 5; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(2000), latencyObservation: LatencyTimeoutObservation));

        // These tasks are added later but will resolve first
        for (int i = 0; i < 4; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout((_) => Task.CompletedTask, latencyObservation: LatencyCompletedObservation));

        await Task.WhenAll(tasks);
        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        // So our time spike safety valve should ignore the hiccup, since later tasks have resolved
        // by the time the safety valve has triggered by the timeout tasks
        Assert.True(adaptiveTimeoutResult < maxTimeout);
        foreach (var t in completedObservations) {
            Assert.InRange(t, 0.0, 50.0);
        }
        foreach (var t in timeoutObservations) {
            Assert.InRange(t, 0.0, 1000.1);
        }
        return;
        
        void LatencyCompletedObservation(double latency) => completedObservations.Add(latency);
        void LatencyTimeoutObservation(double latency) => timeoutObservations.Add(latency);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_ThrowWhenExcessiveTimeouts() {
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromMilliseconds(500);
        var minTimeout = TimeSpan.Zero;
        var numSamples = 5;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 2, throwIfExcessiveTimeouts: true);

        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout((_) => Task.CompletedTask));

        await Task.WhenAll(tasks);

        for (int i = 0; i < 20; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(1000)));

        await Assert.ThrowsAsync<ExcessiveTimeoutsException>(async () => await Task.WhenAll(tasks));
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_DoNotThrowWhenExcessiveTimeouts() {
        var tasks = new List<Task>();
        var maxTimeout = TimeSpan.FromMilliseconds(500);
        var minTimeout = TimeSpan.Zero;
        var numSamples = 5;
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), numSamples, 1000, 2, throwIfExcessiveTimeouts: false);

        for (int i = 0; i < numSamples; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout((_) => Task.CompletedTask));

        await Task.WhenAll(tasks);

        for (int i = 0; i < 20; i++)
            tasks.Add(adaptiveTimeout.ExecuteWithTimeout(async (_) => await Task.Delay(1000)));

        await Task.WhenAll(tasks);
    }

    [Fact]
    public async Task AdaptiveTimeout_GetAdaptiveTimeout_MinTimeout() {
        var maxTimeout = TimeSpan.FromSeconds(1);
        var minTimeout = TimeSpan.FromSeconds(0.5);
        var adaptiveTimeout = new AdaptiveTimeout(maxTimeout, minTimeout, new TestLogger(_testOutputHelper, Microsoft.Extensions.Logging.LogLevel.Trace), 1, 1000, 1);

        await adaptiveTimeout.ExecuteWithTimeout((_) => Task.CompletedTask);

        var adaptiveTimeoutResult = adaptiveTimeout.GetAdaptiveTimeout();
        Assert.Equal(minTimeout, adaptiveTimeoutResult);
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
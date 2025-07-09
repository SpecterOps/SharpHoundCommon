using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib;

public class AdaptiveTimeout : IDisposable {
    private readonly ExecutionTimeSampler _sampler;
    private readonly TimeSpan _defaultTimeout;
    private readonly int _minSamplesForAdaptiveTimeout;

    public AdaptiveTimeout(TimeSpan defaultTimeout, ILogger log, int sampleCount, int logFrequency, int minSamplesForAdaptiveTimeout) {
        _sampler = new ExecutionTimeSampler(log, sampleCount, logFrequency);
        _defaultTimeout = defaultTimeout;
        _minSamplesForAdaptiveTimeout = minSamplesForAdaptiveTimeout;
    }

    public void ClearSamples() => _sampler.ClearSamples();

    public Task<Result<T>> ExecuteWithTimeout<T>(Func<CancellationToken, T> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public Task<Result> ExecuteWithTimeout(Action<CancellationToken> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public Task<Result<T>> ExecuteWithTimeout<T>(Func<CancellationToken, Task<T>> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public Task<Result> ExecuteWithTimeout(Func<CancellationToken, Task> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public Task<NetAPIResult<T>> ExecuteNetAPIWithTimeout<T>(Func<CancellationToken, NetAPIResult<T>> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteNetAPIWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public Task<SharpHoundRPC.Result<T>> ExecuteRPCWithTimeout<T>(Func<CancellationToken, SharpHoundRPC.Result<T>> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteRPCWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public Task<SharpHoundRPC.Result<T>> ExecuteRPCWithTimeout<T>(Func<CancellationToken, Task<SharpHoundRPC.Result<T>>> func, CancellationToken parentToken = default) =>
        Timeout.ExecuteRPCWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);

    public void Dispose() {
        _sampler.Dispose();
    }

    private double StandardDeviation() {
        if (_sampler.Count < _minSamplesForAdaptiveTimeout)
            return -1;

        return _sampler.StandardDeviation();
    }

    private TimeSpan GetAdaptiveTimeout() {
        // Within 3 standard deviations should be about 99.9% of executions
        // But cap at configured timeout
        // https://en.wikipedia.org/wiki/68%E2%80%9395%E2%80%9399.7_rule
        var stdDiv = StandardDeviation();
        var adaptiveTimeoutMs = stdDiv > 0 ? _sampler.Average() + (stdDiv * 3) : _defaultTimeout.TotalMilliseconds;
        var cappedTimeoutMS = Math.Min(adaptiveTimeoutMs, _defaultTimeout.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(cappedTimeoutMS);
    }
}
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib;

public sealed class AdaptiveTimeout : IDisposable {
    private readonly ExecutionTimeSampler _sampler;
    private readonly ILogger _log;
    private readonly TimeSpan _maxTimeout;
    private readonly bool _useAdaptiveTimeout;
    private readonly int _minSamplesForAdaptiveTimeout;
    private int _clearSamplesDecay;
    private const int TimeSpikePenalty = 2;
    private const int TimeSpikeForgiveness = 1;
    private const int ClearSamplesThreshold = 5;
    private const int StdDevMultiplier = 5;

    public AdaptiveTimeout(TimeSpan maxTimeout, ILogger log, int sampleCount = 100, int logFrequency = 1000, int minSamplesForAdaptiveTimeout = 30, bool useAdaptiveTimeout = true) {
        if (maxTimeout <= TimeSpan.Zero)
            throw new ArgumentException("maxTimeout must be positive", nameof(maxTimeout));
        if (sampleCount <= 0)
            throw new ArgumentException("sampleCount must be positive", nameof(sampleCount));
        if (logFrequency <= 0)
            throw new ArgumentException("logFrequency must be positive", nameof(logFrequency));
        if (minSamplesForAdaptiveTimeout <= 0)
            throw new ArgumentException("minSamplesForAdaptiveTimeout must be positive", nameof(minSamplesForAdaptiveTimeout));
        if (log == null)
            throw new ArgumentNullException(nameof(log));

        _sampler = new ExecutionTimeSampler(log, sampleCount, logFrequency);
        _log = log;
        _maxTimeout = maxTimeout;
        _useAdaptiveTimeout = useAdaptiveTimeout;
        _minSamplesForAdaptiveTimeout = minSamplesForAdaptiveTimeout;
    }

    public void ClearSamples() {
        _clearSamplesDecay = 0;
        _sampler.ClearSamples();
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<Result<T>> ExecuteWithTimeout<T>(Func<CancellationToken, T> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<Result> ExecuteWithTimeout(Action<CancellationToken> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<Result<T>> ExecuteWithTimeout<T>(Func<CancellationToken, Task<T>> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<Result> ExecuteWithTimeout(Func<CancellationToken, Task> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<NetAPIResult<T>> ExecuteNetAPIWithTimeout<T>(Func<CancellationToken, NetAPIResult<T>> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteNetAPIWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<SharpHoundRPC.Result<T>> ExecuteRPCWithTimeout<T>(Func<CancellationToken, SharpHoundRPC.Result<T>> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteRPCWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    /// <summary>
    /// Ignores the result of a function if it runs longer than a budgeted time, unblocking the caller.
    /// Logs aggregate execution time data.
    /// Manages its own timeout.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// Please don't wrap a cached function in this timeout if adaptive timeouts enabled, normal distributions are better.
    /// DO NOT use a single AdaptiveTimeout for multiple functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="func"></param>
    /// <param name="parentToken"></param>
    /// <returns>Returns a Fail result if a task runs longer than its budgeted time.</returns>
    public async Task<SharpHoundRPC.Result<T>> ExecuteRPCWithTimeout<T>(Func<CancellationToken, Task<SharpHoundRPC.Result<T>>> func, CancellationToken parentToken = default) {
        var result = await Timeout.ExecuteRPCWithTimeout(GetAdaptiveTimeout(), (timeoutToken) => _sampler.SampleExecutionTime(() => func(timeoutToken)), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess);
        return result;
    }

    public void Dispose() {
        _sampler.Dispose();
    }

    // Within 5 standard deviations will have a conservative lower bound of catching 98% of executions (1 - 1/(k^2 / 2)),
    // regardless of sample shape
    // so long as those samples are independent and identically distributed
    // (and if they're not, our TimeSpikeSafetyValve should provide us with some adaptability)
    // But we'll cap at configured timeout
    // https://modelassist.epixanalytics.com/space/EA/26574957/Tchebysheffs+Rule
    // https://en.wikipedia.org/wiki/Independent_and_identically_distributed_random_variables
    public TimeSpan GetAdaptiveTimeout() {
        if (!_useAdaptiveTimeout || _sampler.Count < _minSamplesForAdaptiveTimeout)
            return _maxTimeout;

        var stdDev = _sampler.StandardDeviation();
        var adaptiveTimeoutMs = _sampler.Average() + (stdDev * StdDevMultiplier);
        var cappedTimeoutMS = Math.Min(adaptiveTimeoutMs, _maxTimeout.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(cappedTimeoutMS);
    }

    // AdaptiveTimeout will not respond well to rapid spikes in execution time
    // imagine the wrapped function very regularly executes in 10ms
    // then suddenly starts taking a regular 100ms
    // this is fine (if it fits in our max timeout budget), and we shouldn't block
    // so we should create a safety valve in case this happens to reset our data samples
    private void TimeSpikeSafetyValve(bool isSuccess) {
        if (isSuccess) {
            _clearSamplesDecay -= TimeSpikeForgiveness;
            _clearSamplesDecay = Math.Max(0, _clearSamplesDecay);
        }
        else
            _clearSamplesDecay += TimeSpikePenalty;

        if (_clearSamplesDecay >= ClearSamplesThreshold) {
            ClearSamples();
            _log.LogTrace("Time spike safety valve event at timeout {CurrentTimeout}.", GetAdaptiveTimeout());
        }
    }
}
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib;

public sealed class AdaptiveTimeout : IDisposable {
    private readonly ExecutionTimeSampler _sampler;
    private readonly TimeSpan _defaultTimeout;
    private readonly bool _useAdaptiveTimeout;
    private readonly int _minSamplesForAdaptiveTimeout;
    private int _clearSamplesDecay;
    private const int ClearSamplesThreshold = 8;

    public AdaptiveTimeout(TimeSpan defaultTimeout, ILogger log, int sampleCount, int logFrequency, int minSamplesForAdaptiveTimeout, bool useAdaptiveTimeout = true) {
        _sampler = new ExecutionTimeSampler(log, sampleCount, logFrequency);
        _defaultTimeout = defaultTimeout;
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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
    /// DO NOT wrap a cached function in this timeout if adaptive timeouts enabled - it demands an approximately normal distribution of execution time.
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

    private TimeSpan GetAdaptiveTimeout() {
        // Within 3 standard deviations should be about 99.9% of executions
        // But cap at configured timeout
        // https://en.wikipedia.org/wiki/68%E2%80%9395%E2%80%9399.7_rule
        if (!_useAdaptiveTimeout || _sampler.Count < _minSamplesForAdaptiveTimeout)
            return _defaultTimeout;

        var stdDiv = _sampler.StandardDeviation();
        var adaptiveTimeoutMs = _sampler.Average() + (stdDiv * 3);
        var cappedTimeoutMS = Math.Min(adaptiveTimeoutMs, _defaultTimeout.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(cappedTimeoutMS);
    }

    // AdaptiveTimeout will not respond well to rapid spikes in execution time
    // imagine the wrapped function very regularly executes in 10ms
    // then suddenly starts taking a regular 100ms
    // this is fine (if it fits in our timeout budget), and we shouldn't block
    // so we should create a safety valve in case this happens to reset our data samples
    private void TimeSpikeSafetyValve(bool isSuccess) {
        if (isSuccess)
            _clearSamplesDecay = Math.Max(0, --_clearSamplesDecay);
        else
            _clearSamplesDecay += 2;

        if (_clearSamplesDecay >= ClearSamplesThreshold)
            ClearSamples();
    }
}
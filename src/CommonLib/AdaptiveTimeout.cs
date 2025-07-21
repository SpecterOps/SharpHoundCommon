using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Exceptions;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib;

public sealed class AdaptiveTimeout : IDisposable {
    private readonly ExecutionTimeSampler _sampler;
    private readonly ConcurrentQueue<DateTime> _latestSuccessTimestamps;
    private readonly ILogger _log;
    private readonly TimeSpan _maxTimeout;
    private readonly bool _useAdaptiveTimeout;
    private readonly int _minSamplesForAdaptiveTimeout;
    private readonly bool _throwIfExcessiveTimeouts;
    private int _timeSpikeDecay;
    private const int TimeSpikePenalty = 2;
    private const int TimeSpikeForgiveness = 1;
    private const int TimeSpikeThreshold = 5;
    private const int ExcessiveTimeoutsThreshold = 7;
    private const int StdDevMultiplier = 5;
    private const int CountOfLatestSuccessToKeep = 4;

    public AdaptiveTimeout(TimeSpan maxTimeout, ILogger log, int sampleCount = 100, int logFrequency = 1000, int minSamplesForAdaptiveTimeout = 30, bool useAdaptiveTimeout = true, bool throwIfExcessiveTimeouts = false) {
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
        _latestSuccessTimestamps = new ConcurrentQueue<DateTime>();
        _log = log;
        _maxTimeout = maxTimeout;
        _minSamplesForAdaptiveTimeout = minSamplesForAdaptiveTimeout;
        _useAdaptiveTimeout = useAdaptiveTimeout;
        _throwIfExcessiveTimeouts = throwIfExcessiveTimeouts;
    }

    public void ClearSamples() {
        Interlocked.Exchange(ref _timeSpikeDecay, 0);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                return func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                return func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                return func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteNetAPIWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                return func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteRPCWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                return func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
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
        DateTime startTime = DateTime.MinValue; // for ordinal tracking; see use in TimeSpikeSafetyValve
        var result = await Timeout.ExecuteRPCWithTimeout(GetAdaptiveTimeout(), (timeoutToken) =>
            _sampler.SampleExecutionTime(() => {
                startTime = DateTime.Now;
                return func(timeoutToken);
            }), parentToken);
        TimeSpikeSafetyValve(result.IsSuccess, startTime);
        return result;
    }

    public void Dispose() {
        _sampler.Dispose();
    }

    // Within 5 standard deviations will have a conservative lower bound of catching 96% of executions (1 - 1/5^2),
    // regardless of sample shape
    // so long as those samples are independent and identically distributed
    // (and if they're not, our TimeSpikeSafetyValve should provide us with some adaptability)
    // But the effective collection rate is probably closer to 98+%
    // (in part because we don't need to filter out "too fast" outliers)
    // But we'll cap at configured maximum timeout
    // https://modelassist.epixanalytics.com/space/EA/26574957/Tchebysheffs+Rule
    // https://en.wikipedia.org/wiki/Independent_and_identically_distributed_random_variables
    public TimeSpan GetAdaptiveTimeout() {
        if (!UseAdaptiveTimeout())
            return _maxTimeout;

        try {
            var stdDev = _sampler.StandardDeviation();
            var adaptiveTimeoutMs = _sampler.Average() + (stdDev * StdDevMultiplier);
            var cappedTimeoutMS = Math.Min(adaptiveTimeoutMs, _maxTimeout.TotalMilliseconds);
            return TimeSpan.FromMilliseconds(cappedTimeoutMS);
        }
        catch (Exception ex) {
            _log.LogError(ex, "Error calculating adaptive timeout, defaulting to max timeout.");
            return _maxTimeout;
        }
    }

    // AdaptiveTimeout will not respond well to rapid spikes in execution time
    // imagine the wrapped function very regularly executes in 10ms
    // then suddenly starts taking a regular 100ms
    // this is fine (if it fits in our max timeout budget), and we shouldn't timeout
    // so we should create a safety valve in case this happens to reset our data samples
    private void TimeSpikeSafetyValve(bool isSuccess, DateTime startTime) {
        if (isSuccess) {
            AtomicDecrementWithFloor(ref _timeSpikeDecay, TimeSpikeForgiveness);
            AddLatestSuccessTimestamp(startTime);
        }
        else {
            Interlocked.Add(ref _timeSpikeDecay, TimeSpikePenalty);

            if (Volatile.Read(ref _timeSpikeDecay) >= TimeSpikeThreshold) {
                if (EnoughSuccessesSince(startTime)) {
                    // Time spike is in the past now, no action needed
                    // This happens when earlier calls report back timeouts
                    // but we've since seen sufficent successful calls completed in the time between
                    _log.LogTrace("Time spike hiccup spotted but since recovered.");
                    Interlocked.Exchange(ref _timeSpikeDecay, 0);
                }
                else {
                    TriggerTimeSpikeEvent();
                }
            }
        }
    }

    private void TriggerTimeSpikeEvent() {
        // Most recent calls made have been timing out
        // If adaptive timeout is in play when a spike in timeout events occurs,
        // flush our samples and back off to the max timeout until we have enough new ones
        // to rebuild our data confidence
        if (UseAdaptiveTimeout()) {
            _log.LogTrace("Time spike safety valve event at timeout {CurrentTimeout}.", GetAdaptiveTimeout());
            ClearSamples();
        }

        // Otherwise, if we're using the max configured timeout already and this spike in timeout events is still occuring,
        // log it and maybe throw an error if so configuredx
        else if (Volatile.Read(ref _timeSpikeDecay) >= ExcessiveTimeoutsThreshold) {
            _log.LogWarning("This call is frequently running over the maximum allowed timeout of {MaxTimeout}.", _maxTimeout);
            Interlocked.Exchange(ref _timeSpikeDecay, 0);

            if (_throwIfExcessiveTimeouts)
                throw new ExcessiveTimeoutsException($"This call is frequently running over the maximum allowed timeout of {_maxTimeout}.");
        }
    }

    private bool UseAdaptiveTimeout() {
        return _useAdaptiveTimeout && _sampler.Count >= _minSamplesForAdaptiveTimeout;
    }

    private void AddLatestSuccessTimestamp(DateTime startTime) {
        while (_latestSuccessTimestamps.Count >= CountOfLatestSuccessToKeep) {
            _latestSuccessTimestamps.TryDequeue(out var _);
        }

        _latestSuccessTimestamps.Enqueue(startTime);
    }

    private bool EnoughSuccessesSince(DateTime startTime) {
        return _latestSuccessTimestamps.All(t => t >= startTime);
    }

    // AI-generated code
    // Effectively accomplishes:
    // // Interlocked.Add(ref location, -decrement);
    // // Interlocked.Exchange(ref location, Math.Max(floor, location));
    // But since the above doesn't guarnantee atomicity, we need to be more clever.
    // This method will continually check the very latest value in <location>,
    // compute the new expected value after the decrement,
    // and try to replace <location> with this new value.
    // If it fails for any reason (race condition), it does all this again
    // until it wins the race.
    // This is however supposedly still much faster than using lock objects.
    // // Example:
    /*
        // target == 0
        // 1: this thread
        // 2: interceding thread
        
        1: do {
        1: var initialVal = target;
        2: target = 2;
        1: var computedVal = Math.Max(0, initialVal - 1);   // computedVal == 0
        1: } while (target != initialVal);

        // target changed midway thru the op (2 != 0) and so isn't changed by CompareExchange, retry loop:

        1: var initialVal = target; // 2
        1: var computedVal = Math.Max(0, initialVal - 1);   // computedVal == 1
        1: } while (target != initialVal);

        // target (2) == initialVal (2), assign target to 1 and exit loop
    */
    public static void AtomicDecrementWithFloor(ref int target, int decrement, int floor = 0) {
        int initialValue, computedValue;
        do {
            initialValue = Volatile.Read(ref target);
            computedValue = Math.Max(floor, initialValue - decrement);
        }
        // If target is modified by another thread between initialValue assignment and now, continue loop
        while (Interlocked.CompareExchange(ref target, computedValue, initialValue) != initialValue);
    }
}
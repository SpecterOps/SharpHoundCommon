using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib;

/// <summary>
/// Holds a rolling sample of execution times on a function, providing and logging data aggregates.
/// </summary>
public class ExecutionTimeSampler : IDisposable {
    private readonly ILogger _log;
    private readonly int _sampleCount;
    private readonly int _logFrequency;
    private int _samplesSinceLastLog;
    private ConcurrentQueue<double> _samples;

    public int Count => _samples.Count;

    public ExecutionTimeSampler(ILogger log, int sampleCount, int logFrequency) {
        _log = log;
        _sampleCount = sampleCount;
        _logFrequency = logFrequency;
        _samplesSinceLastLog = 0;
        _samples = new ConcurrentQueue<double>();
    }

    public void ClearSamples() {
        Log(flush: true);
        _samples = new ConcurrentQueue<double>();
    }

    public double StandardDeviation() {
        double average = _samples.Average();
        double sumOfSquaresOfDifferences = _samples.Select(val => (val - average) * (val - average)).Sum();
        double stddiv = Math.Sqrt(sumOfSquaresOfDifferences / _samples.Count);

        return stddiv;
    }

    public double Average() => _samples.Average();

    public async Task<T> SampleExecutionTime<T>(Func<Task<T>> func) {
        var stopwatch = Stopwatch.StartNew();
        var result = await func.Invoke();
        stopwatch.Stop();
        AddTimeSample(stopwatch.Elapsed);

        return result;
    }

    public async Task SampleExecutionTime(Func<Task> func) {
        var stopwatch = Stopwatch.StartNew();
        await func.Invoke();
        stopwatch.Stop();
        AddTimeSample(stopwatch.Elapsed);
    }

    public T SampleExecutionTime<T>(Func<T> func) {
        var stopwatch = Stopwatch.StartNew();
        var result = func.Invoke();
        stopwatch.Stop();
        AddTimeSample(stopwatch.Elapsed);

        return result;
    }

    public void SampleExecutionTime(Action func) {
        var stopwatch = Stopwatch.StartNew();
        func.Invoke();
        stopwatch.Stop();
        AddTimeSample(stopwatch.Elapsed);
    }

    public void Dispose() {
        Log(flush: true);
    }

    private void AddTimeSample(TimeSpan timeSpan) {
        while (_samples.Count >= _sampleCount) {
            _samples.TryDequeue(out _);
        }

        _samples.Enqueue(timeSpan.TotalMilliseconds);
        Interlocked.Increment(ref _samplesSinceLastLog);

        Log();
    }

    private void Log(bool flush = false) {
        if ((flush || _samplesSinceLastLog >= _logFrequency) && _samples.Count > 0) {
            try {
                _log.LogInformation("Execution time Average: {Average}ms, StdDiv: {StandardDeviation}ms", _samples.Average(), StandardDeviation());
            }
            catch (Exception ex) {
                _log.LogWarning("Failed to calculate execution time statistics: {Error}", ex.Message);
            }

            Interlocked.Exchange(ref _samplesSinceLastLog, 0);
        }
    }
}
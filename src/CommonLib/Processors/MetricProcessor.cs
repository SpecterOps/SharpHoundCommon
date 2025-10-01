using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors;

public interface IMetricWriter {
    Task WriteAsync(List<Metric> metrics);
}

public enum MetricType {
    Counter,
    Gauge,
    Histogram
}

public class Metric {
    public string Name { get; set; } = string.Empty;
    public MetricType MetricType { get; set; }
    public double Value { get; set; }
    public Dictionary<string, string>? Labels { get; set; } = null;
}

public class MetricProcessor {
    private readonly ConcurrentBag<Metric> _metrics = [];
    private readonly TimeSpan _flushInterval;
    private readonly IMetricWriter _writer;
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    

    public MetricProcessor(IMetricWriter writer, TimeSpan? flushInterval = null) {
        _writer = writer;
        _flushInterval = flushInterval ?? TimeSpan.FromSeconds(60);
        _ = RunFlushLoop();
    }

    private async Task RunFlushLoop() {
        while (!_cancellationTokenSource.IsCancellationRequested) {
            await Task.Delay(_flushInterval);
            await FlushAsync();
        }
    }

    public void Record(string name, double value, MetricType metricType = MetricType.Gauge,
        Dictionary<string, string> labels = null) {
        _metrics.Add(new Metric { Name = name, Value = value, MetricType = metricType, Labels = labels});
    }

    public async Task FlushAsync() {
        if (_metrics.IsEmpty) {
            return;
        }

        var batch = new List<Metric>();
        while (_metrics.TryTake(out var metric)) {
            batch.Add(metric);
        }

        try {
            await _writer.WriteAsync(batch);
        }
        catch {
            // Don't crash program if we cannot write metrics
        }
    }

    public void Stop() => _cancellationTokenSource.Cancel();
}
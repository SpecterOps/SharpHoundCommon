using System;
using System.Threading;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Services;

public static class MetricAggregatorExtensions {
    public static MetricAggregator Create(MetricDefinition definition) =>
        definition switch {
            CounterDefinition => new CounterAggregator(),
            GaugeDefinition => new GaugeAggregator(),
            CumulativeHistogramDefinition ch => new CumulativeHistogramAggregator(ch.Buckets),
            _ => throw new ArgumentOutOfRangeException(nameof(definition),
                $"Unknown metric type {definition.GetType().Name}")
        };
}

public abstract class MetricAggregator {
    public abstract void Observe(double value);
    public abstract object Snapshot();
}

public sealed class CounterAggregator : MetricAggregator {
    private long _value;

    public override void Observe(double value) => Interlocked.Add(ref _value, (long)value);
    public override object Snapshot() => _value;
}

public sealed class GaugeAggregator : MetricAggregator {
    private double _value;
    
    public override void Observe(double value) => _value = value;
    public override object Snapshot() => _value;
}

public record struct HistogramSnapshot(double[] Bounds, long[] Counts, long TotalCount, double Sum);

public sealed class CumulativeHistogramAggregator(double[] bounds) : MetricAggregator {
    private readonly long[] _bucketCounts = new long[bounds.Length + 1]; // Includes the Inf+ bucket
    private long _count;
    private double _sum;

    public override void Observe(double value) {
        // this along with the following line, finds the correct bucket the value should be placed in.
        // If the value is defined as a specific bucket, binary search returns it. If it is not found,
        // it returns the compliment of the position it should be at. with a simple check we can undo
        // that compliment if it is what is found.
        var idx = Array.BinarySearch(bounds, value);
        if (idx < 0) idx = ~idx;
        _bucketCounts[idx]++;
        _count++;
        _sum += value;
    }
    
    public override object Snapshot() => SnapshotHistogram();

    public HistogramSnapshot SnapshotHistogram() =>
        new(bounds, _bucketCounts, _count, _sum);
}
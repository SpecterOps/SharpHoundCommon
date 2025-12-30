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
    public abstract void Flush(IMetricWriter writer);
}

public sealed class CounterAggregator : MetricAggregator {
    private long _value;

    public override void Observe(double value) => Interlocked.Add(ref _value, (long)value);
    public override void Flush(IMetricWriter writer) => writer.FlushCounter(_value);
}

public sealed class GaugeAggregator : MetricAggregator {
    private double _value;
    
    public override void Observe(double value) => _value = value;
    public override void Flush(IMetricWriter writer) => writer.FlushGauge(_value);
}

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

    public override void Flush(IMetricWriter writer) {
        long cumulative = 0;
        var cumulativeValues = new long[_bucketCounts.Length];
        for (var i = 0; i < _bucketCounts.Length; i++) {
            cumulative += _bucketCounts[i];
            cumulativeValues[i] = cumulative;
        }
        writer.FlushCumulativeHistogram(cumulativeValues, _count, _sum);
    }
}
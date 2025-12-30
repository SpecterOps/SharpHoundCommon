using System;
using System.Collections.Generic;

namespace SharpHoundCommonLib.Models;

public abstract record MetricDefinition(
    string Name, 
    IReadOnlyList<string> LabelNames);

public sealed record CounterDefinition(string Name, IReadOnlyList<string> LabelNames) : MetricDefinition(Name, LabelNames);
public sealed record GaugeDefinition(string Name, IReadOnlyList<string> LabelNames) : MetricDefinition(Name, LabelNames);

public sealed record CumulativeHistogramDefinition(string Name, double[] InitBuckets, IReadOnlyList<string> LabelNames) : MetricDefinition(Name, LabelNames) {
    public double[] Buckets { get; } = NormalizeBuckets(InitBuckets);

    private static double[] NormalizeBuckets(double[] buckets) {
        if (buckets is null || buckets.Length == 0)
            throw new ArgumentException("Histogram buckets cannot be empty");

        var copy = (double[])buckets.Clone();
        Array.Sort(copy);

        for (var i = 1; i < copy.Length; i++) {
            if (copy[i] <= copy[i - 1])
                throw new ArgumentException("Histogram buckets must be strictly increasing");
        }

        return copy;
    }
};

// Currently Native Histograms are not supported
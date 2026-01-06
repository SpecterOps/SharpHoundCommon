using System;
using System.Collections.Generic;
using System.Text;

namespace SharpHoundCommonLib.Models;

public readonly record struct LabelValues(string[] Values) {
    public string ToDisplayString(IReadOnlyList<string> labelNames, string additionalName = null, string additionalValue = null) {
        if (labelNames.Count == 0)
            return string.Empty;
        
        if (labelNames.Count != Values.Length)
            return $"{{Improper Observation Labels, LabelNamesCount: {labelNames.Count}, LabelValuesCount: {Values.Length}}}";

        var sb = new StringBuilder();
        sb.Append('{');
        for (var i = 0; i < labelNames.Count; i++) {
            if (i > 0)
                sb.Append(',');
            
            sb.Append(labelNames[i])
                .Append(':')
                .Append(Values[i]);
        }

        if (!string.IsNullOrEmpty(additionalName) && !string.IsNullOrEmpty(additionalValue)) {
            sb.Append(',').Append(additionalName).Append(':').Append(additionalValue);
        }
        
        sb.Append('}');
        return sb.ToString();
    }
};

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
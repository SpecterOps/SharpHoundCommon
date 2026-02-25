using System;
using System.Collections.Generic;
using System.Linq;
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
                .Append("=\"")
                .Append(Values[i])
                .Append('"');
        }

        if (!string.IsNullOrEmpty(additionalName) && !string.IsNullOrEmpty(additionalValue)) {
            sb.Append(',').Append(additionalName).Append("=\"").Append(additionalValue).Append('"');
        }
        
        sb.Append('}');
        return sb.ToString();
    }

    public Dictionary<string, string> ToDictionary(IReadOnlyList<string> labelNames,
        IReadOnlyList<string> additionalLabelNames = null, IReadOnlyList<string> additionalLabelValues = null) {
        if (labelNames.Count == 0)
            return new Dictionary<string, string>();
        
        if (labelNames.Count != Values.Length)
            return new Dictionary<string, string>{{"invalid_labels", "label_name_and_count_do_not_match"}};

        if (additionalLabelNames == null || additionalLabelValues == null ||
            additionalLabelNames.Count != additionalLabelValues.Count)
            return labelNames.Zip(Values, (name, value) => new { name, value }).ToDictionary(x => x.name, x => x.value);
        
        var names = new List<string>(labelNames);
        var values = new List<string>(Values);
        names.AddRange(additionalLabelNames);
        values.AddRange(additionalLabelValues);
        return names.Zip(values, (name, value) => new {name, value}).ToDictionary(x => x.name, x => x.value);
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
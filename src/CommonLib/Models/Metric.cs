using System.Collections.Generic;

namespace SharpHoundCommonLib.Models;

public abstract record Metric {
    private Metric() { }
    
    public sealed record DoubleMetric(string Name, MetricType Type, double Value, IDictionary<string, string> Labels) : Metric;
    public sealed record VectorMetric(string Name, MetricType Type, IEnumerable<double> Value, IDictionary<string, string> Labels) : Metric;
}

public enum MetricType {
    Counter,
    Gauge,
    Histogram
}

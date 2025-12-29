using System.Collections.Generic;

namespace SharpHoundCommonLib.Models;

public abstract record Metric {
    private Metric() { }

    public sealed record DoubleMetric(
        string Name,
        MetricType Type,
        double Value,
        IDictionary<string, string> Labels) : Metric;

    public sealed record DictionaryMetric(
        string Name,
        MetricType Type,
        IDictionary<string, double> Value,
        IDictionary<string, string> Labels) : Metric;
}

public enum MetricType {
    Counter,
    Gauge,
    ClassicHistogram,
    // Currently Native Histograms are not supported for scraping.
    // Histogram,
}

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Processors;

public class MetricProcessor(IMetricWriter writer) : IMetricProcessor {
    private readonly ConcurrentDictionary<string, Metric> _metrics = [];


    public void Record(string name, object value, MetricType metricType = MetricType.Counter,
        IDictionary<string, string> labels = null) {
        _metrics.AddOrUpdate(name, (_) => CreateMetric(name, value, metricType, labels),
            (_, metric) => UpdateMetric(name, value, metric, metricType, labels));
    }

    private static Metric CreateMetric(string name, object value, MetricType metricType = MetricType.Counter,
            IDictionary<string, string> labels = null) => metricType switch {
            MetricType.Counter when value is double v => new Metric.DoubleMetric(name, metricType, v, labels),
            MetricType.Counter => new Metric.DoubleMetric(name, metricType, -1, labels),
            MetricType.Gauge when value is double v => new Metric.DoubleMetric(name, metricType, v, labels),
            MetricType.Gauge => new Metric.DoubleMetric(name, metricType, -1, labels),
            MetricType.Histogram when value is IEnumerable<double> v => new Metric.VectorMetric(name, metricType, v, labels),
            MetricType.Histogram => new Metric.VectorMetric(name, metricType, [], labels),
            _ => new Metric.DoubleMetric(name, metricType, -1, labels)
        };

    private static Metric UpdateMetric(string name, object value, Metric existingMetric, MetricType metricType = MetricType.Counter,
        IDictionary<string, string> labels = null) => existingMetric switch {
            Metric.DoubleMetric m when metricType is MetricType.Counter && value is double v =>
                m with { Labels = CombineLabels(m.Labels, labels), Value = m.Value + v },
            Metric.DoubleMetric m when metricType is MetricType.Gauge && value is double v =>
                m with { Labels = CombineLabels(m.Labels, labels), Value = v },
            Metric.DoubleMetric m when metricType is MetricType.Counter => m,
            Metric.VectorMetric m when metricType is MetricType.Histogram && value is double v =>
                m with { Labels = CombineLabels(m.Labels, labels), Value = m.Value.Concat([v]) },
            Metric.VectorMetric m when metricType is MetricType.Histogram && value is IEnumerable<double> v =>
                m with { Labels = CombineLabels(m.Labels, labels), Value = m.Value.Concat(v) },
            Metric.VectorMetric m => m,
            _ => new Metric.DoubleMetric(name, metricType, -1, labels)
        };

    private static IDictionary<string, string> CombineLabels(IDictionary<string, string> labels1 = null,
        IDictionary<string, string> labels2 = null) {
        if (labels1 != null && labels2 != null) {
             return labels1.Concat(labels2.Where( x=> !labels1.ContainsKey(x.Key))).ToDictionary(x=>x.Key, x=>x.Value);
        }
        return labels1 ?? labels2;
    }

    public async Task FlushAsync() {
        if (_metrics.IsEmpty) {
            return;
        }

        try {
            await writer.WriteAsync(_metrics);
        }
        catch {
            // Don't crash program if we cannot write metrics
        }
    }
}
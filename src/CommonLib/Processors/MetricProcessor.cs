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
            MetricType.ClassicHistogram when value is IDictionary<string, double> v => new Metric.DictionaryMetric(name, metricType, v, labels),
            MetricType.ClassicHistogram => new Metric.DictionaryMetric(name, metricType, [], labels),
            _ => new Metric.DoubleMetric(name, metricType, -1, labels)
        };

    private static Metric UpdateMetric(string name, object value, Metric existingMetric, MetricType metricType = MetricType.Counter,
        IDictionary<string, string> labels = null) => existingMetric switch {
            Metric.DoubleMetric m when metricType is MetricType.Counter && value is double v =>
                m with { Labels = CombineLabels(m.Labels, labels), Value = m.Value + v },
            Metric.DoubleMetric m when metricType is MetricType.Gauge && value is double v =>
                m with { Labels = CombineLabels(m.Labels, labels), Value = v },
            Metric.DoubleMetric m when metricType is MetricType.Counter => m,
            Metric.DictionaryMetric m when metricType is MetricType.ClassicHistogram && value is IDictionary<string, double> v =>
            m with { Labels = CombineLabels(m.Labels, labels), Value = CombineObservations(m.Value, v) },
            Metric.DictionaryMetric m => m,
            _ => new Metric.DoubleMetric(name, metricType, -1, labels)
        };

    private static IDictionary<string, string> CombineLabels(IDictionary<string, string> labels1 = null,
        IDictionary<string, string> labels2 = null) {
        if (labels1 != null && labels2 != null) {
             return labels1.Concat(labels2.Where( x=> !labels1.ContainsKey(x.Key))).ToDictionary(x=>x.Key, x=>x.Value);
        }
        return labels1 ?? labels2 ?? [];
    }

    private static IDictionary<string, double> CombineObservations(IDictionary<string, double> observations1 = null,
        IDictionary<string, double> observations2 = null) {
        if (observations1 == null || observations2 == null) return observations1 ?? observations2 ?? [];
        foreach (var pair in observations2) {
            if (!observations1.ContainsKey(pair.Key))
                observations1[pair.Key] = pair.Value;
            else
                observations1[pair.Key] += pair.Value;
        }

        return observations1;
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
using System.Collections.Concurrent;
using System.Threading.Tasks;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricWriter {
    Task WriteAsync(ConcurrentDictionary<string, MetricObservation> metrics);
    Task FlushGauge(double value);
    Task FlushCounter(long value);
    Task FlushCumulativeHistogram(long[] values, long count, double sum);
}
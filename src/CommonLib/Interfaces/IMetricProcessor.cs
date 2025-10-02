using System.Collections.Generic;
using System.Threading.Tasks;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricProcessor {
    void Record(string name, object value, MetricType metricType = MetricType.Counter, IDictionary<string, string> labels = null);
    Task FlushAsync();
}
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricRouter {
    void Observe(int definitionId, double value, LabelValues labelValues);
    void Flush();
}
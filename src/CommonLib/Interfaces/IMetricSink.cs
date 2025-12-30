using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricSink {
    void Observe(in MetricObservation.DoubleMetricObservation observation);
    void Flush();
}

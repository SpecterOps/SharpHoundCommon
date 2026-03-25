using System;
using System.Text;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Services;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricWriter {
    void StringBuilderAppendMetric(
        StringBuilder builder,
        MetricDefinition definition,
        LabelValues labelValues,
        MetricAggregator aggregator,
        DateTimeOffset timestamp,
        string timestampOutputString = "yyyy-MM-dd HH:mm:ss.fff"
    );
}
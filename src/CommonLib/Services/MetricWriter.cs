using System;
using System.Text;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Services;

public class MetricWriter : IMetricWriter {
    public void StringBuilderAppendMetric(StringBuilder builder, MetricDefinition definition, LabelValues labelValues,
        MetricAggregator aggregator, DateTimeOffset timestamp, string timestampOutputString = "yyyy-MM-dd HH:mm:ss.fff") {
        var labelText = labelValues.ToDisplayString(definition.LabelNames);
        builder.AppendFormat("{0} {1}{2} = {{{3}}}\n", timestamp.ToString(timestampOutputString), definition.Name, labelText, aggregator.Snapshot());
    }
}
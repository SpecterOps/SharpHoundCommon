using System;
using System.Text;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Services;

public class MetricWriter : IMetricWriter {
    public void StringBuilderAppendMetric(StringBuilder builder, MetricDefinition definition, LabelValues labelValues,
        MetricAggregator aggregator, DateTimeOffset timestamp, string timestampOutputString = "yyyy-MM-dd HH:mm:ss.fff") {
        var labelText = labelValues.ToDisplayString(definition.LabelNames);
        if (aggregator is CumulativeHistogramAggregator cha) {
            CumulativeHistogramAppend(builder, definition, labelText, cha, timestamp, timestampOutputString);
        } else {
            DefaultAppend(builder, definition, labelText, aggregator, timestamp, timestampOutputString);
        }
    }

    private static void CumulativeHistogramAppend(
        StringBuilder builder,
        MetricDefinition definition,
        string labelText,
        CumulativeHistogramAggregator aggregator,
        DateTimeOffset timestamp,
        string timestampOutputString) {
            long cumulativeValue = 0;

            var snapshot = aggregator.SnapshotHistogram();

            for (var i = 0; i < snapshot.Bounds.Length; i++) {
                cumulativeValue += snapshot.Counts[i];

                builder.AppendFormat("{0} {1}{2}{{le=\"{3}\"}} = {4}\n",
                    timestamp.ToString(timestampOutputString),
                    definition.Name + "_bucket",
                    labelText,
                    snapshot.Bounds[i],
                    cumulativeValue);
            }

            builder.AppendFormat("{0} {1}{2}{{le=\"+Inf\"}} = {3}\n",
                timestamp.ToString(timestampOutputString),
                definition.Name + "_bucket",
                labelText,
                snapshot.TotalCount);

            builder.AppendFormat("{0} {1}{2} = {3}\n",
                timestamp.ToString(timestampOutputString),
                definition.Name + "_sum",
                labelText,
                snapshot.Sum);

            builder.AppendFormat("{0} {1}{2} = {3}\n",
                timestamp.ToString(timestampOutputString),
                definition.Name + "_count",
                labelText,
                snapshot.TotalCount);
        }


    private static void DefaultAppend(
        StringBuilder builder, 
        MetricDefinition definition, 
        string labelText, 
        MetricAggregator aggregator, 
        DateTimeOffset timestamp, 
        string timestampOutputString) => 
        builder.AppendFormat("{0} {1}{2} = {{{3}}}\n", timestamp.ToString(timestampOutputString),
            definition.Name, labelText, aggregator.Snapshot());
}
using System;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Services;

public class MetricWriter(ILogger log = null) : IMetricWriter {
    public void StringBuilderAppendMetric(StringBuilder builder, MetricDefinition definition, LabelValues labelValues,
        MetricAggregator aggregator, DateTimeOffset timestamp, string timestampOutputString = "yyyy-MM-dd HH:mm:ss.fff") {
        switch (aggregator) {
            case GaugeAggregator g:
                DefaultAppend(builder, definition, labelValues.ToDisplayString(definition.LabelNames),
                    g, timestamp, timestampOutputString);
                break;
            case CounterAggregator c:
                DefaultAppend(builder, definition,
                    labelValues.ToDisplayString(definition.LabelNames), c, timestamp, timestampOutputString);
                break;
            case CumulativeHistogramAggregator cha:
                CumulativeHistogramAppend(builder, definition, labelValues, cha,
                    timestamp, timestampOutputString);
                break;
            default: 
                log?.LogWarning($"No implementation of this Aggregator in {nameof(StringBuilderAppendMetric)}.");
                break;
        }
    }

    private static void CumulativeHistogramAppend(
        StringBuilder builder,
        MetricDefinition definition,
        LabelValues labelValues,
        CumulativeHistogramAggregator aggregator,
        DateTimeOffset timestamp,
        string timestampOutputString) {
            long cumulativeValue = 0;
            var defaultLabelText = labelValues.ToDisplayString(definition.LabelNames);

            var snapshot = aggregator.SnapshotHistogram();

            for (var i = 0; i < snapshot.Bounds.Length; i++) {
                cumulativeValue += snapshot.Counts[i];

                if (labelValues.Values.Length > 0) {
                    builder.AppendFormat("{0} {1}{2} = {3}\n",
                        timestamp.ToString(timestampOutputString),
                        definition.Name + "_bucket",
                        labelValues.ToDisplayString(definition.LabelNames, "le", snapshot.Bounds[i].ToString(CultureInfo.InvariantCulture)),
                        cumulativeValue);
                } else {
                    builder.AppendFormat("{0} {1}{2}{{le=\"{3}\"}} = {4}\n",
                        timestamp.ToString(timestampOutputString),
                        definition.Name + "_bucket",
                        defaultLabelText,
                        snapshot.Bounds[i],
                        cumulativeValue);
                }
            }

            if (labelValues.Values.Length > 0) {
                    builder.AppendFormat("{0} {1}{2} = {3}\n",
                        timestamp.ToString(timestampOutputString),
                        definition.Name + "_bucket",
                        labelValues.ToDisplayString(definition.LabelNames, "le", "+Inf"),
                        snapshot.TotalCount);
                
            } else {
                    builder.AppendFormat("{0} {1}{2}{{le=\"+Inf\"}} = {3}\n",
                        timestamp.ToString(timestampOutputString),
                        definition.Name + "_bucket",
                        defaultLabelText,
                        snapshot.TotalCount);
            }

            builder.AppendFormat("{0} {1}{2} = {3}\n",
                timestamp.ToString(timestampOutputString),
                definition.Name + "_sum",
                defaultLabelText,
                snapshot.Sum);

            builder.AppendFormat("{0} {1}{2} = {3}\n",
                timestamp.ToString(timestampOutputString),
                definition.Name + "_count",
                defaultLabelText,
                snapshot.TotalCount);
        }


    private static void DefaultAppend(
        StringBuilder builder, 
        MetricDefinition definition, 
        string labelText, 
        MetricAggregator<double> aggregator, 
        DateTimeOffset timestamp, 
        string timestampOutputString) => 
        builder.AppendFormat("{0} {1}{2} = {{{3}}}\n", timestamp.ToString(timestampOutputString),
            definition.Name, labelText, aggregator.Snapshot());
    
    private static void DefaultAppend(
        StringBuilder builder, 
        MetricDefinition definition, 
        string labelText, 
        MetricAggregator<long> aggregator, 
        DateTimeOffset timestamp, 
        string timestampOutputString) => 
        builder.AppendFormat("{0} {1}{2} = {{{3}}}\n", timestamp.ToString(timestampOutputString),
            definition.Name, labelText, aggregator.Snapshot());
}
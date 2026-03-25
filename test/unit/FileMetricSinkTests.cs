using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Moq;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Services;
using Xunit;

namespace CommonLibTest;

public class SimpleMetricWriter : IMetricWriter {
    public void StringBuilderAppendMetric(StringBuilder builder, MetricDefinition definition, LabelValues labelValues,
        MetricAggregator aggregator, DateTimeOffset timestamp,
        string timestampOutputString = "yyyy-MM-dd HH:mm:ss.fff") {
        switch (aggregator) {
            case GaugeAggregator g:
                builder.Append(
                    $"DefinitionType: {definition.GetType()}, DefinitionName: {definition.Name}, AggregatorType: {aggregator.GetType()}, AggregatorSnapshotType: {g.Snapshot().GetType()}\n");
                break;
            case CounterAggregator c:
                builder.Append(
                    $"DefinitionType: {definition.GetType()}, DefinitionName: {definition.Name}, AggregatorType: {aggregator.GetType()}, AggregatorSnapshotType: {c.Snapshot().GetType()}\n");
                break;
            case CumulativeHistogramAggregator cha:
                builder.Append(
                    $"DefinitionType: {definition.GetType()}, DefinitionName: {definition.Name}, AggregatorType: {aggregator.GetType()}, AggregatorSnapshotType: {cha.Snapshot().GetType()}\n");
                break;
            default:
                builder.Append(
                    $"DefinitionType: {definition.GetType()}, DefinitionName: {definition.Name}, AggregatorType: {aggregator.GetType()}, AggregatorSnapshotType: Unknown Aggregator Type\n");
                break;
        }
    }
}

public class FileMetricSinkTests {
    [Theory]
    [MemberData(nameof(FileMetricSinkTestData.FlushStringCases), MemberType = typeof(FileMetricSinkTestData))]
    public void FileMetricSink_Returns_Expected_Flush_String(
        MetricDefinition[] definitions,
        MetricObservation.DoubleMetricObservation[] observations,
        string[] expectedOutputs,
        string[] unexpectedOutputs) {
        // setup
        var sinkOptions = new FileMetricSinkOptions {
            FlushWriter = true,
        };
        var textWriter = new StringWriter();
        var metricWriter = new SimpleMetricWriter();
        var sink = new FileMetricSink(definitions, textWriter, metricWriter, sinkOptions);
        
        // act
        foreach (var observation in observations) {
            sink.Observe(observation);
        }
        sink.Flush();
        var output = textWriter.ToString();
        
        // assert
        foreach (var expectedOutput in expectedOutputs) {
            Assert.Contains(expectedOutput, output);
        }

        foreach (var unexpectedOutput in unexpectedOutputs) {
            Assert.DoesNotContain(unexpectedOutput, output);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FileMetricSink_Does_Not_Flush_Writer_With_AutoFlush_False(bool autoFlush) {
        // setup
        var sinkOptions = new FileMetricSinkOptions {
            FlushWriter = autoFlush,
        };
        var writerMoq = new Mock<TextWriter>(MockBehavior.Strict);
        writerMoq.Setup(w => w.Write(It.IsAny<string>())).Verifiable();
        writerMoq.Setup(w => w.Flush()).Verifiable();
        var metricWriter = new SimpleMetricWriter();
        MetricDefinition[] definitions = [new CounterDefinition("counter_definition", ["name"])];
        var observation = new MetricObservation.DoubleMetricObservation(0, 1, ["value"]);
        var sink = new FileMetricSink(definitions, writerMoq.Object, metricWriter, sinkOptions);
        
        // act
        sink.Observe(observation);
        sink.Flush();
        
        // assert
        writerMoq.Verify(w => w.Write(It.IsAny<string>()), Times.Once);
        if (autoFlush)
            writerMoq.Verify(w => w.Flush(), Times.Once);
        else
            writerMoq.Verify(w => w.Flush(), Times.Never);
    }
}

public static class FileMetricSinkTestData {
    public static IEnumerable<object[]> FlushStringCases => [
        // Observations are flushed
        [
            new MetricDefinition[] {
                new CounterDefinition("counter_definition", ["value"]),
                new GaugeDefinition("gauge_definition", ["value"]),
            },
            new[] {
                new MetricObservation.DoubleMetricObservation(0, 1, []),
                new MetricObservation.DoubleMetricObservation(1, 1, []),
            },
            new[] {
                "Metric Flush: ",
                "========================================",
                "DefinitionType: SharpHoundCommonLib.Models.CounterDefinition, DefinitionName: counter_definition, AggregatorType: SharpHoundCommonLib.Services.CounterAggregator, AggregatorSnapshotType: System.Int64\n",
                "DefinitionType: SharpHoundCommonLib.Models.GaugeDefinition, DefinitionName: gauge_definition, AggregatorType: SharpHoundCommonLib.Services.GaugeAggregator, AggregatorSnapshotType: System.Double\n",
            },
            Array.Empty<string>(),
        ],
        // Unobserved Metrics are not flushed
        [
            new MetricDefinition[] {
                new CounterDefinition("counter_definition", ["value"]),
                new GaugeDefinition("gauge_definition", ["value"]),
            },
            new[] {
                new MetricObservation.DoubleMetricObservation(0, 1, []),
            },
            new[] {
                "Metric Flush: ",
                "========================================",
                "DefinitionType: SharpHoundCommonLib.Models.CounterDefinition, DefinitionName: counter_definition, AggregatorType: SharpHoundCommonLib.Services.CounterAggregator, AggregatorSnapshotType: System.Int64\n",
            },
            new[] {
                "DefinitionType: SharpHoundCommonLib.Models.GaugeDefinition, DefinitionName: gauge_definition, AggregatorType: SharpHoundCommonLib.Services.GaugeAggregator, AggregatorSnapshotType: System.Double\n",
            },
        ],
        // Cumulative Histogram Returns HistogramSnapshot
        [
            new MetricDefinition[] {
                new CounterDefinition("counter_definition", ["value"]),
                new GaugeDefinition("gauge_definition", ["value"]),
                new CumulativeHistogramDefinition("cumulative_histogram_definition", [1, 2, 3], ["value"]),
            },
            new[] {
                new MetricObservation.DoubleMetricObservation(0, 1, []),
                new MetricObservation.DoubleMetricObservation(1, 1, []),
                new MetricObservation.DoubleMetricObservation(2, 1, []),
            },
            new[] {
                "Metric Flush: ",
                "========================================",
                "DefinitionType: SharpHoundCommonLib.Models.CounterDefinition, DefinitionName: counter_definition, AggregatorType: SharpHoundCommonLib.Services.CounterAggregator, AggregatorSnapshotType: System.Int64\n",
                "DefinitionType: SharpHoundCommonLib.Models.GaugeDefinition, DefinitionName: gauge_definition, AggregatorType: SharpHoundCommonLib.Services.GaugeAggregator, AggregatorSnapshotType: System.Double\n",
                "DefinitionType: SharpHoundCommonLib.Models.CumulativeHistogramDefinition, DefinitionName: cumulative_histogram_definition, AggregatorType: SharpHoundCommonLib.Services.CumulativeHistogramAggregator, AggregatorSnapshotType: SharpHoundCommonLib.Services.HistogramSnapshot\n",
            },
            Array.Empty<string>(),
        ],
    ];
}
using System;
using System.Collections.Generic;
using System.Text;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Services;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest;


public class MetricAggregatorTests(ITestOutputHelper output) {

    [Theory]
    [MemberData(nameof(MetricAggregatorTestData.CreateTestData), MemberType = typeof(MetricAggregatorTestData))]
    public void MetricAggregatorExtensions_Create_Creates_Proper_Aggregator(MetricDefinition definition,
        MetricAggregator expectedAggregator) {
        // setup
        // act
        var aggregator = MetricAggregatorExtensions.Create(definition);
        
        // assert
        Assert.IsType(expectedAggregator.GetType(), aggregator);
    }

    [Fact]
    public void MetricAggregatorExtensions_Creates_Throws_Exception_For_Unimplemented_MetricDefinition() {
        // setup
        var newMetricDefinition = new UnimplementedMetricDefinition("unimplemented", ["value1"]);
        
        // act and assert
        Assert.Throws<ArgumentOutOfRangeException>(() => MetricAggregatorExtensions.Create(newMetricDefinition));
    }

    [Theory]
    [MemberData(nameof(MetricAggregatorTestData.ObserveAndSnapshotTests),
        MemberType = typeof(MetricAggregatorTestData))]
    public void MetricAggregator_Observe_and_Snapshot_Tests(MetricAggregator aggregator,
       double[] observations, object expectedSnapshot) {
        // setup
        foreach (var observation in observations) {
            aggregator.Observe(observation);
        }
        
        // act
        var snapshot = aggregator.Snapshot();
        
        // assert
        if (expectedSnapshot is HistogramSnapshot ehs && snapshot is HistogramSnapshot ahs) {
            Assert.Equal(ehs.TotalCount, ahs.TotalCount);
            Assert.Equal(ehs.Sum, ahs.Sum);
            Assert.Equal(ehs.Bounds, ahs.Bounds);
            Assert.Equal(ehs.Counts, ahs.Counts);
        } else {
            Assert.Equal(expectedSnapshot, snapshot); 
        }
        
    }

    private string snapShotArrays(double[] bounds, long[] counts) {
        var builder = new StringBuilder();
        builder.Append("bounds: [ ");
        Iterate(builder, bounds);
        builder.Append(" ],  counts: [ ");
        Iterate(builder, counts);
        builder.Append(" ]");
        return builder.ToString();
            
        
        void Iterate<T>(StringBuilder sb, T[] os) {
            var first = true;

            for (var i = 0; i < os.Length; i++) {
                if (!first)
                    builder.Append(", ");
                
                builder.Append(os[i]);
                first = false;
            }
        }
    }
    
    
    private record UnimplementedMetricDefinition(string Name, IReadOnlyList<string> LabelNames) : MetricDefinition(Name, LabelNames) {}
    
}

public static class MetricAggregatorTestData {
    public static IEnumerable<object[]> CreateTestData => [
        [
            new CounterDefinition("counter_name", ["value"]),
            new CounterAggregator(),
        ],
        [
            new GaugeDefinition("gauge_name", ["value"]),
            new GaugeAggregator(),
        ],
        [
            new CumulativeHistogramDefinition("cumulative_histogram_name", [1, 2, 3], ["value"]),
            new CumulativeHistogramAggregator([1, 2, 3])
        ],
    ];

    public static IEnumerable<object[]> ObserveAndSnapshotTests => [
        [
            new CounterAggregator(),
            new[] {
                1.0,
                2.0,
                1.0,
                4.0,
            },
            8L
        ],
        [
            new GaugeAggregator(),
            new[] {
                1.0,
                2.0,
                1.0,
                
            },
            1.0
        ],
        [
            new CumulativeHistogramAggregator([1, 2, 3, 4]),
            new[] {
                1.0,
                1.0,
                3.0,
                3.0,
                2.0,
            },
            // Ensure Aggregation does not happen on observation or snapshot
            new HistogramSnapshot([1, 2, 3, 4], [2, 1, 2, 0, 0],  5, 10)
        ],
    ];
}
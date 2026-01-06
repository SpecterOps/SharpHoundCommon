using System;
using SharpHoundCommonLib.Models;
using Xunit;

namespace CommonLibTest;

public class MetricDefinitionTests {

    [Fact]
    public void LabelValues_EmptyLabelNames_Returns_Empty() {
        // setup
        var labelValues = new LabelValues(["value1", "value2"]);
        string[] labelNames = [];
        
        // act
        var output = labelValues.ToDisplayString(labelNames);
        
        // assert
        Assert.Empty(output);
    }

    [Fact]
    public void LabelValues_MoreLabelNames_Returns_Error() {
        // setup
        var labelValues = new LabelValues(["value1", "value2"]);
        string[] labelNames = ["value1", "value2", "value3"];
        
        // act
        var output = labelValues.ToDisplayString(labelNames);
        
        // assert
        Assert.Equal($"{{Improper Observation Labels, LabelNamesCount: {labelNames.Length}, LabelValuesCount: {labelValues.Values.Length}}}", output);
    }

    [Fact]
    public void LabelValues_MoreLabelValues_Returns_Error() {
        // setup
        var labelValues = new LabelValues(["value1", "value2", "value3"]);
        string[] labelNames = ["value1", "value2"];
        
        // act
        var output = labelValues.ToDisplayString(labelNames);
        
        // assert
        Assert.Equal($"{{Improper Observation Labels, LabelNamesCount: {labelNames.Length}, LabelValuesCount: {labelValues.Values.Length}}}", output);
    }
    
    [Fact]
    public void LabelValues_ToDisplayString() {
        // setup
        var labelValues = new LabelValues(["value1", "value2", "value3"]);
        string[] labelNames = ["name1", "name2", "name3"];
        
        // act
        var output = labelValues.ToDisplayString(labelNames);
        
        // assert
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output);
    }

    [Fact]
    public void LabelValues_ToDisplayString_Additional_Values_Requires_Both() {
        // setup
        var labelValues = new LabelValues(["value1", "value2", "value3"]);
        string[] labelNames = ["name1", "name2", "name3"];
        
        // act
        var output1 = labelValues.ToDisplayString(labelNames, string.Empty);
        var output2 = labelValues.ToDisplayString(labelNames, "");
        var output3 = labelValues.ToDisplayString(labelNames, "additional_name");
        var output4 = labelValues.ToDisplayString(labelNames, additionalValue: string.Empty);
        var output5 = labelValues.ToDisplayString(labelNames, additionalValue: "");
        var output6 = labelValues.ToDisplayString(labelNames, additionalValue: "additional_value");
        var output7 = labelValues.ToDisplayString(labelNames, "additional_name", "additional_value");
        
        // assert
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output1);
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output2);
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output3);
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output4);
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output5);
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\"}", output6);
        Assert.Equal("{name1=\"value1\",name2=\"value2\",name3=\"value3\",additional_name=\"additional_value\"}", output7);
    }

    [Fact]
    public void Definitions_Properly_Assign_Values() {
        // setup
        const string name = "definitionName";
        string[] labelNames = ["name1", "name2", "name3" ];
        double[] buckets = [0, 1, 2, 3];
        
        // act
        var counter = new CounterDefinition(name, labelNames);
        var gauge = new GaugeDefinition(name, labelNames);
        var histogram = new CumulativeHistogramDefinition(name, buckets, labelNames);
        
        // assert
        Assert.Equal(name, counter.Name);
        Assert.Equal(name, gauge.Name);
        Assert.Equal(name, histogram.Name);
        Assert.Equal(labelNames, counter.LabelNames);
        Assert.Equal(labelNames, gauge.LabelNames);
        Assert.Equal(labelNames, histogram.LabelNames);
        Assert.Equal(buckets.Length, histogram.Buckets.Length);
        for (var i = 0; i < buckets.Length; ++i) {
            Assert.Equal(buckets[i], histogram.Buckets[i]);
        }
        
    }

    [Fact]
    public void CumulativeHistogramDefinition_NormalizesBuckets() {
        // setup
        double[] initBuckets = [5, 4, 3, 2, 1];
        
        // act
        var definition = new CumulativeHistogramDefinition("name", initBuckets, []);
        Array.Sort(initBuckets);
        
        // assert
        Assert.Equal(initBuckets.Length, definition.Buckets.Length);
        for (var i = 0; i < definition.Buckets.Length; ++i) {
            Assert.Equal(initBuckets[i], definition.Buckets[i]);
        }
    }
}
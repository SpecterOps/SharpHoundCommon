using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Services;
using SharpHoundCommonLib.Static;
using Xunit;

namespace CommonLibTest;

public class MetricRegistryTests {
    [Fact]
    public void TryRegister_Returns_definitionID_if_Success() {
        // setup
        var registry = new MetricRegistry();
        var counter = new CounterDefinition("counter_name", ["value"]);
        var gauge = new GaugeDefinition("gauge_name", ["value"]);

        // act
        var registered1 = registry.TryRegister(counter, out var counterDefinitionId);
        var registered2 = registry.TryRegister(gauge, out var gaugeDefinitionId);
        
        // assert
        Assert.True(registered1);
        Assert.True(registered2);
        Assert.Equal(0, counterDefinitionId);
        Assert.Equal(1, gaugeDefinitionId);
    }

    [Fact]
    public void TryRegister_Gets_Preregistered_Definition_by_Name() {
        // setup
        var registry = new MetricRegistry();
        var counter1 = new CounterDefinition("counter_name", ["value"]);
        var counter2 = new CounterDefinition("counter_name", ["value"]);
        
        // act
        var registered1 = registry.TryRegister(counter1, out var counterDefinitionId1);
        var registered2 = registry.TryRegister(counter2, out var counterDefinitionId2);
        
        // assert
        Assert.True(registered1);
        Assert.True(registered2);
        Assert.Equal(0, counterDefinitionId1);
        Assert.Equal(counterDefinitionId1, counterDefinitionId2);
        Assert.Single(registry.Definitions);
    }

    [Fact]
    public void TryRegister_After_Sealing_Returns_false_and_InvalidId() {
        // setup
        var registry = new MetricRegistry();
        var counter = new CounterDefinition("counter_name", ["value"]);
        var gauge = new GaugeDefinition("gauge_name", ["value"]);
        
        // act
        var registered1 = registry.TryRegister(counter, out var counterDefinitionId);
        registry.Seal();
        var registered2 = registry.TryRegister(gauge, out var gaugeDefinitionId);
        
        // assert
        Assert.True(registered1);
        Assert.False(registered2);
        Assert.Equal(0, counterDefinitionId);
        Assert.Equal(MetricId.InvalidId, gaugeDefinitionId);
        Assert.Single(registry.Definitions);
    }
}
using Moq;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Services;
using Xunit;

namespace CommonLibTest;

public class MetricRouterTests {

    [Theory]
    [InlineData(-1)]
    [InlineData(5)]
    [InlineData(2)]
    public void InvalidIds_Are_Not_Cached_or_Observed(int definitionId) {
        // setup
        MetricDefinition[] definitions = [
            new CounterDefinition("counter_name_1", ["name"]),
            new CounterDefinition("counter_name_2", ["name"]),
        ];
        var labelCacheMoq = new Mock<ILabelValuesCache>();
        var sinkMoq = new Mock<IMetricSink>();
        var router = new MetricRouter(
            definitions,
            [sinkMoq.Object],
            labelCacheMoq.Object
        );

        // act
        router.Observe(definitionId, 1.0, new LabelValues(["value"]));

        // assert
        sinkMoq.Verify(s => s.Observe(in It.Ref<MetricObservation.DoubleMetricObservation>.IsAny), Times.Never());
        labelCacheMoq.Verify(c => c.Intern(It.IsAny<string[]>()), Times.Never());
    }

    [Fact]
    public void LabelValues_Are_Interned_And_Each_Sink_Is_Observed() {
        // setup
        MetricDefinition[] definitions = [
            new CounterDefinition("counter_name_1", ["name"]),
            new CounterDefinition("counter_name_2", ["name"]),
        ];
        var labelCacheMoq = new Mock<ILabelValuesCache>();
        var sinkMoq1 = new Mock<IMetricSink>();
        var sinkMoq2 = new Mock<IMetricSink>();
        var router = new MetricRouter(
            definitions,
            [sinkMoq1.Object, sinkMoq2.Object],
            labelCacheMoq.Object
        );

        // act
        router.Observe(0, 1.0, new LabelValues(["value"]));

        // assert
        labelCacheMoq.Verify(c => c.Intern(It.IsAny<string[]>()), Times.Once());
        sinkMoq1.Verify(s => s.Observe(in It.Ref<MetricObservation.DoubleMetricObservation>.IsAny), Times.Once());
        sinkMoq2.Verify(s => s.Observe(in It.Ref<MetricObservation.DoubleMetricObservation>.IsAny), Times.Once());
    }

    [Fact]
    public void Flush_Calls_Flush_on_Each_Sink() {
        // setup
        MetricDefinition[] definitions = [
        ];
        var labelCacheMoq = new Mock<ILabelValuesCache>();
        var sinkMoq1 = new Mock<IMetricSink>();
        var sinkMoq2 = new Mock<IMetricSink>();
        var router = new MetricRouter(
            definitions,
            [sinkMoq1.Object, sinkMoq2.Object],
            labelCacheMoq.Object
        );

        // act
        router.Flush();

        // assert
        sinkMoq1.Verify(s => s.Flush(), Times.Once());
        sinkMoq2.Verify(s => s.Flush(), Times.Once());
        sinkMoq1.Verify(s => s.Observe(in It.Ref<MetricObservation.DoubleMetricObservation>.IsAny), Times.Never());
        sinkMoq2.Verify(s => s.Observe(in It.Ref<MetricObservation.DoubleMetricObservation>.IsAny), Times.Never());
        labelCacheMoq.Verify(c => c.Intern(It.IsAny<string[]>()), Times.Never());
    }
}
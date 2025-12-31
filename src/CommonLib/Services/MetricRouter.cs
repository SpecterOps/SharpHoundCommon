using System.Collections.Generic;
using System.Linq;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Services;

public sealed class MetricRouter(IReadOnlyList<MetricDefinition> definitions, IEnumerable<IMetricSink> sinks) : IMetricRouter {
    private readonly int _definitionCount = definitions.Count;
    private readonly IMetricSink[] _sinks = sinks.ToArray();
    
    // TODO MC: See if this boosts runtime, may need more metrics to see an appreciable difference.
    // In JIT Complication, can remove some of the overhead of calling
    // [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Observe(int definitionId, double value, LabelValues labelValues) {
        // check to see if metric is registered, handles negative values and IDs greater than those registered.
        if ((uint)definitionId >= (uint)_definitionCount)
            return;
        
        var obs = new MetricObservation.DoubleMetricObservation(definitionId, value, labelValues);

        foreach (var sink in _sinks) 
            sink.Observe(obs);
    }

    public void Flush() {
        foreach (var sink in _sinks)
            sink.Flush();
    }
}

public sealed class NoOpMetricRouter : IMetricRouter {
    public static readonly NoOpMetricRouter Instance = new();
    private NoOpMetricRouter() { }

    public void Observe(int definitionId, double value, LabelValues labelValues) {
        // intentionally empty
    }

    public void Flush() {
        // intentionally empty
    }
}

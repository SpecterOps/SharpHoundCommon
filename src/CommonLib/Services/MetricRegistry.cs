using System.Collections.Generic;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Static;

namespace SharpHoundCommonLib.Services;

public sealed class MetricRegistry : IMetricRegistry {
    private readonly List<MetricDefinition> _metrics = [];
    private readonly Dictionary<string, int> _nameToId = new();
    private bool _sealed;

    public IReadOnlyList<MetricDefinition> Definitions => _metrics;

    public bool TryRegister(MetricDefinition definition, out int definitionId) {
        definitionId = MetricId.InvalidId;
        if (_sealed) return false;

        if (_nameToId.TryGetValue(definition.Name, out definitionId))
            return true;

        definitionId = _metrics.Count;
        _metrics.Add(definition);
        _nameToId[definition.Name] = definitionId;
        return true;
    }
    
    internal void Seal() => _sealed = true;
}

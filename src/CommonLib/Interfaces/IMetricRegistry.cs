using System.Collections.Generic;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricRegistry {
    bool TryRegister(MetricDefinition definition, out int definitionId);
    IReadOnlyList<MetricDefinition> Definitions { get; }
}
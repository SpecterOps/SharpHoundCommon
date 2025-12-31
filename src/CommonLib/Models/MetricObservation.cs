namespace SharpHoundCommonLib.Models;

public abstract record MetricObservation {
    private MetricObservation() { }
    
    public readonly record struct DoubleMetricObservation(
        int DefinitionId,
        double Value,
        LabelValues LabelsValues);
}

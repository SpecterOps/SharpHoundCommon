namespace SharpHoundCommonLib.Interfaces;

public interface IMetricRouter {
    void Observe(int definitionId, double value, string[] labelValues);
    void Flush();
}
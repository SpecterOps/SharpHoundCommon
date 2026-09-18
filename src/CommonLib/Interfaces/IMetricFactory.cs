namespace SharpHoundCommonLib.Interfaces;

public interface IMetricFactory {
    IMetricRouter CreateMetricRouter();
}
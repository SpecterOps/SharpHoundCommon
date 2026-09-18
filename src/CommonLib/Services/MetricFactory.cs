using SharpHoundCommonLib.Interfaces;

namespace SharpHoundCommonLib.Services;

public sealed class MetricFactory(IMetricRouter router) : IMetricFactory {
    private readonly IMetricRouter _router = router;
    
    public IMetricRouter CreateMetricRouter() => _router; 
}

public sealed class NoOpMetricFactory : IMetricFactory {
    public static readonly NoOpMetricFactory Instance = new();
    private NoOpMetricFactory() { }
    public IMetricRouter CreateMetricRouter() => NoOpMetricRouter.Instance;
}

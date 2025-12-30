using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Services;

namespace SharpHoundCommonLib.Static;

public static class Metrics {
    private static IMetricFactory _factory = NoOpMetricFactory.Instance;

    public static IMetricFactory Factory {
        get => _factory;
        set => _factory = value ?? NoOpMetricFactory.Instance;
    }
}


public static class MetricId {
    public const int InvalidId = -1;
}

public static class LdapMetrics {
    public static int RequestLatency = MetricId.InvalidId;
    public static int ConcurrentRequests = MetricId.InvalidId;
    public static int RequestsTotal = MetricId.InvalidId;
}
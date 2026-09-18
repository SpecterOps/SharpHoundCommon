using System.Threading;
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

public static class LdapMetrics {
    private static int _inFlightRequests;
    
    public static int InFlightRequest => _inFlightRequests;
    
    public static int IncrementInFlight() => Interlocked.Increment(ref _inFlightRequests);
    public static int DecrementInFlight() => Interlocked.Decrement(ref _inFlightRequests);
    public static void ResetInFlight() => Interlocked.Exchange(ref _inFlightRequests, 0);
}


public static class MetricId {
    public const int InvalidId = -1;
}

public static class LdapMetricDefinitions {
    public static int RequestLatency = MetricId.InvalidId;
    public static int ConcurrentRequests = MetricId.InvalidId;
    public static int RequestsTotal = MetricId.InvalidId;
    public static int FailedRequests = MetricId.InvalidId;
    public static int UnresolvablePrincipals = MetricId.InvalidId;
}

public static class AdaptiveTimeoutDefinitions {
    public static int TimeoutsTotal = MetricId.InvalidId;
}
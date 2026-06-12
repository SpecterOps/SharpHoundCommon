using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Static;

public static class DefaultMetricRegistry {
    public static void RegisterDefaultMetrics(this IMetricRegistry registry) {
        // LDAP Metrics
        registry.TryRegister(
            new CounterDefinition(
                Name: "ldap_total_requests",
                LabelNames: ["location", "identifier"]),
            out LdapMetricDefinitions.RequestsTotal);
        
        registry.TryRegister(
            new CounterDefinition(
                Name: "ldap_failed_requests",
                LabelNames: ["location", "identifier"]),
            out LdapMetricDefinitions.FailedRequests);
        
        registry.TryRegister(
            new GaugeDefinition(
                Name: "ldap_concurrent_requests",
                LabelNames: ["location", "identifier"]),
            out LdapMetricDefinitions.ConcurrentRequests);
         
        registry.TryRegister(
            new CumulativeHistogramDefinition(
                Name: "ldap_request_duration_milliseconds",
                InitBuckets: [100, 250, 500, 1000, 2500, 5000],
                LabelNames: ["location", "identifier"]),
            out LdapMetricDefinitions.RequestLatency);
        
        registry.TryRegister(
            new CounterDefinition(
                Name: "ldap_total_unresolvable_principals",
                LabelNames: ["location"]),
            out LdapMetricDefinitions.UnresolvablePrincipals);
        
        registry.TryRegister(
            new CounterDefinition(
                Name: "adaptive_timeouts_total",
                LabelNames: ["location"]),
            out AdaptiveTimeoutDefinitions.TimeoutsTotal);
    }
}
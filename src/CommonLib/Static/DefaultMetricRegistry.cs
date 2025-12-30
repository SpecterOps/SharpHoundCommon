using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Static;

public static class DefaultMetricRegistry {
    public static void RegisterDefaultMetrics(this IMetricRegistry registry) {
        // LDAP Metrics
        registry.TryRegister(
            new CounterDefinition(
                Name: "ldap_total_requests",
                LabelNames: ["processor"]),
            out LdapMetrics.RequestsTotal);
        
        registry.TryRegister(
            new GaugeDefinition(
                Name: "ldap_concurrent_requests",
                LabelNames: ["processor"]),
            out LdapMetrics.ConcurrentRequests);
         
        registry.TryRegister(
            new CumulativeHistogramDefinition(
                Name: "ldap_request_duration_seconds",
                InitBuckets: [0.1, 0.25, 0.5, 1, 2.5, 5],
                LabelNames: ["processor"]),
            out LdapMetrics.RequestLatency);
    }
}
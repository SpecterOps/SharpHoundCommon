using System.Collections.Concurrent;
using System.Threading.Tasks;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Interfaces;

public interface IMetricWriter {
    Task WriteAsync(ConcurrentDictionary<string, Metric> metrics);
}
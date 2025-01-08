#nullable enable
namespace SharpHoundRPC.Registry;

using System.Collections.Generic;


public class StrategyExecutorResult<T>
{
    public IEnumerable<T>? Results { get; set; } = null;
    public IEnumerable<StrategyResult<T>>? FailureAttempts { get; set; } = null;
    public bool WasSuccessful = false;
}
#nullable disable
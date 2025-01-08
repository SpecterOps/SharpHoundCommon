#nullable enable

using System;
using System.Collections.Generic;

namespace SharpHoundRPC.Registry;

/// <summary>
/// Represents the result of attempting to execute an enumeration strategy
/// </summary>
/// <typeparam name="T">The type of data being enumerated</typeparam>
public class StrategyResult<T>
{
    /// <summary>
    /// The type of strategy that was attempted
    /// </summary>
    public Type StrategyType { get; set; }

    /// <summary>
    /// Indicates whether the strategy executed successfully.
    /// Only meaningful if WasAttempted is true.
    /// </summary>
    public bool WasSuccessful { get; set; } = false;

    /// <summary>
    /// A human-readable description of why the strategy failed.
    /// May include details about port availability, access denied, etc.
    /// </summary>
    public string? FailureReason { get; set; } = null;

    /// <summary>
    /// The results returned by the strategy if it executed successfully.
    /// Will be null or empty if strategy failed or wasn't attempted.
    /// </summary>
    public IEnumerable<T>? Results { get; set; }

    /// <summary>
    /// Creates a new instance of StrategyAttemptResult with default values
    /// </summary>
    public StrategyResult(Type strategyType)
    {
        StrategyType = strategyType;
    }

    /// <summary>
    /// Returns a string representation of the attempt result for logging/debugging
    /// </summary>
    public override string ToString()
    {
        return $"Strategy: {StrategyType?.Name ?? "Unknown"}, " +
               $"Successful: {WasSuccessful}, " +
               (!string.IsNullOrEmpty(FailureReason) ? $", Reason: {FailureReason}" : "");
    }
}
#nullable disable

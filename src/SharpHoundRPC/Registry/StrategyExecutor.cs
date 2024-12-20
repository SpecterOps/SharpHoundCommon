#nullable enable
namespace SharpHoundRPC.Registry;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;


public class StrategyExecutor
{
    public async Task<StrategyExecutorResult<T>> CollectAsync<T, TQuery>(
        string targetMachine,
        IEnumerable<TQuery> queries,
        IEnumerable<ICollectionStrategy<T, TQuery>> strategies)
    {
        var attempts = new List<StrategyResult<T>>();

        foreach (var strategy in strategies)
        {
            var attempt = new StrategyResult<T>(strategy.GetType());
            var (canExecute, reason) = await strategy.CanExecute(targetMachine).ConfigureAwait(false);

            if (!canExecute)
            {
                attempt.FailureReason = reason;
                attempts.Add(attempt);
                continue;
            }

            try
            {
                var results = await strategy.ExecuteAsync(targetMachine, queries).ConfigureAwait(false);

                attempt.WasSuccessful = true;
                attempt.Results = results;

                return new StrategyExecutorResult<T>
                {
                    Results = results,
                    FailureAttempts = attempts,
                    WasSuccessful = true
                };
            }
            catch (Exception ex)
            {
                attempt.FailureReason = $"Collector failed: {ex.Message}.\nInner Exception: {ex.InnerException}";
            }

            attempts.Add(attempt);
        }

        return new StrategyExecutorResult<T>
        {
            Results = null,
            FailureAttempts = attempts
        };
    }
}
#nullable disable

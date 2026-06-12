#nullable enable
namespace SharpHoundRPC.Registry {
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IStrategyExecutor
    {
        Task<StrategyExecutorResult<T>> CollectAsync<T, TQuery>(
            string targetMachine,
            IEnumerable<TQuery> queries,
            IEnumerable<ICollectionStrategy<T, TQuery>> strategies);
    }
    
    public class StrategyExecutor : IStrategyExecutor {
        public async Task<StrategyExecutorResult<T>> CollectAsync<T, TQuery>(
            string targetMachine,
            IEnumerable<TQuery> queries,
            IEnumerable<ICollectionStrategy<T, TQuery>> strategies) {
            var attempts = new List<StrategyResult<T>>();

            foreach (var strategy in strategies) {
                var attempt = new StrategyResult<T>(strategy.GetType());
                var (canExecute, reason) = await strategy.CanExecute(targetMachine).ConfigureAwait(false);

                if (!canExecute) {
                    attempt.FailureReason = reason;
                    attempts.Add(attempt);
                    continue;
                }

                try {
                    var results = await strategy.ExecuteAsync(targetMachine, queries).ConfigureAwait(false);

                    return new StrategyExecutorResult<T> {
                        Results = results,
                        FailureAttempts = attempts,
                        WasSuccessful = true,
                        SuccessfulStrategy =  strategy.GetType()
                    };
                } catch (Exception ex) {
                    var innerException = ex.InnerException != null
                        ? $"\nInner Exception: {ex.InnerException}"
                        : string.Empty;

                    attempt.FailureReason = $"Collector failed: {ex.Message}.{innerException}";
                }

                attempts.Add(attempt);
            }

            return new StrategyExecutorResult<T> {
                FailureAttempts = attempts,
                WasSuccessful = false,
            };
        }
    }
#nullable disable
}
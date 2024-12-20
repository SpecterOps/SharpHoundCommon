#nullable enable
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SharpHoundRPC.Registry;


/// <summary>
/// Strategy for collecting data of type <typeparamref name="T"/> using queries of type <typeparamref name="TQuery"/>.
/// </summary>
/// <typeparam name="T">The type of data to collect</typeparam>
/// <typeparam name="TQuery">The type of query used to collect the data</typeparam>

public interface ICollectionStrategy<T, TQuery>
{
    /// <summary>
    /// Checks if this strategy can be executed against the target machine.
    /// </summary>
    /// <param name="targetMachine">Target machine name or IP</param>
    /// <returns>Whether the strategy can execute and reason if it cannot</returns>
    Task<(bool canExecute, string reason)> CanExecute(string targetMachine);

    /// <summary>
    /// Executes the strategy to collect data from the target machine.
    /// </summary>
    /// <param name="targetMachine">Target machine name or IP</param>
    /// <param name="queries">Queries specifying what data to collect</param>
    /// <returns>Collection of results</returns>
    Task<IEnumerable<T>> ExecuteAsync(string targetMachine, IEnumerable<TQuery> queries);
}
#nullable disable
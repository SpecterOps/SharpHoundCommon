using System;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib;

public static class Timeout {
    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<Result<T>> ExecuteWithTimeout<T>(TimeSpan timeout, Func<CancellationToken, T> func, CancellationToken parentToken = default) {
        // cts will cancel its token if the parentToken is cancelled
        // a default parentToken will never cancel so should noop this CreateLinkedTokenSource
        var cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        var task = Task.Factory.StartNew(() => func(cts.Token), cts.Token, TaskCreationOptions.None, TaskScheduler.Current);
        await Task.WhenAny(task, Task.Delay(timeout, cts.Token));
        cts.Cancel();

        if (task.IsCompleted) {
            try {
                return Result<T>.Ok(await task);
            }
            catch (OperationCanceledException) { }
        }

        if (parentToken.IsCancellationRequested)
            return Result<T>.Fail("Cancellation requested");
        else
            return Result<T>.Fail("Timeout");
    }

    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<Result> ExecuteWithTimeout(TimeSpan timeout, Action<CancellationToken> func, CancellationToken parentToken = default) {
        // cts will cancel its token if the parentToken is cancelled
        // a default parentToken will never cancel so should noop this CreateLinkedTokenSource
        var cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        var task = Task.Factory.StartNew(() => func(cts.Token), cts.Token, TaskCreationOptions.None, TaskScheduler.Current);
        await Task.WhenAny(task, Task.Delay(timeout, cts.Token));
        cts.Cancel();

        if (task.IsCompleted) {
            try {
                await task;
                return Result.Ok();
            }
            catch (OperationCanceledException) { }
        }

        if (parentToken.IsCancellationRequested)
            return Result.Fail("Cancellation requested");
        else
            return Result.Fail("Timeout");
    }

    // These two ExecuteWithTimeout functions should perform equivalently -
    // they both create a new task from a function arg
    // But where the one below can invoke an async function directly to spawn the Task
    // The one above spawns a Task from a synchronous function.
    // The caller shouldn't have to worry about which they're using however,
    // the compiler should figure it out intrinsically

    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<Result<T>> ExecuteWithTimeout<T>(TimeSpan timeout, Func<CancellationToken, Task<T>> func, CancellationToken parentToken = default) {
        // cts will cancel its token if the parentToken is cancelled
        // a default parentToken will never cancel so should noop this CreateLinkedTokenSource
        var cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        var task = func.Invoke(cts.Token);
        await Task.WhenAny(task, Task.Delay(timeout, cts.Token));
        cts.Cancel();

        if (task.IsCompleted) {
            try {
                return Result<T>.Ok(await task);
            }
            catch (OperationCanceledException) { }
        }

        if (parentToken.IsCancellationRequested)
            return Result<T>.Fail("Cancellation requested");
        else
            return Result<T>.Fail("Timeout");
    }

    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<Result> ExecuteWithTimeout(TimeSpan timeout, Func<CancellationToken, Task> func, CancellationToken parentToken = default) {
        // cts will cancel its token if the parentToken is cancelled
        // a default parentToken will never cancel so should noop this CreateLinkedTokenSource
        var cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        var task = func.Invoke(cts.Token);
        await Task.WhenAny(task, Task.Delay(timeout, cts.Token));
        cts.Cancel();

        if (task.IsCompleted) {
            try {
                await task;
                return Result.Ok();
            }
            catch (OperationCanceledException) { }
        }

        if (parentToken.IsCancellationRequested)
            return Result.Fail("Cancellation requested");
        else
            return Result.Fail("Timeout");
    }

    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<NetAPIResult<T>> ExecuteNetAPIWithTimeout<T>(TimeSpan timeout, Func<CancellationToken, NetAPIResult<T>> func) {
        var result = await ExecuteWithTimeout(timeout, func);
        if (result.IsSuccess)
            return result.Value;
        else
            return NetAPIResult<T>.Fail(result.Error);
    }

    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<SharpHoundRPC.Result<T>> ExecuteRPCWithTimeout<T>(TimeSpan timeout, Func<CancellationToken, SharpHoundRPC.Result<T>> func) {
        var result = await ExecuteWithTimeout(timeout, func);
        if (result.IsSuccess)
            return result.Value;
        else
            return SharpHoundRPC.Result<T>.Fail(result.Error);
    }

    /// <summary>
    /// Returns a Fail result if a task runs longer than its budgeted time.
    /// A cancellation token is passed to the executing function so it may exit cleanly if timeout is reached.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="timeout"></param>
    /// <param name="func"></param>
    /// <returns></returns>
    public static async Task<SharpHoundRPC.Result<T>> ExecuteRPCWithTimeout<T>(TimeSpan timeout, Func<CancellationToken, Task<SharpHoundRPC.Result<T>>> func) {
        var result = await ExecuteWithTimeout(timeout, func);
        if (result.IsSuccess)
            return result.Value;
        else
            return SharpHoundRPC.Result<T>.Fail(result.Error);
    }
}
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SharpHoundCommonLib {
    public static class ResultExtensions {

        /// <summary>
        /// Used to lift and transform the result. If the previous result is a success the action is run, if not the
        /// chain is short-circuited.
        /// </summary>
        /// <param name="result">The incoming result type.</param>
        /// <param name="func">The new method to be run.</param>
        /// <typeparam name="TI">The incoming type param.</typeparam>
        /// <typeparam name="TO">The outgoing type param.</typeparam>
        /// <returns>A <see cref="Result{TO}"/> that may be in a success or failed state.</returns>
        public static Result<TO> Bind<TI, TO>(
            this Result<TI> result,
            Func<TI, Result<TO>> func) => !result.IsSuccess ? Result<TO>.Fail(result.Error) : func(result.Value);

        /// <summary>
        /// An asynchronous version of Bind. Used to lift and transform a result. If the input result is a success, the
        /// action is run. Otherwise, the chain is short-circuited./>
        /// </summary>
        /// <param name="resultTask">The incoming result task that can be run.</param>
        /// <param name="func">The method used to lift and transform the incoming result.</param>
        /// <typeparam name="TI">The incoming type param.</typeparam>
        /// <typeparam name="TO">The outgoing type param.</typeparam>
        /// <returns>A <see cref="Result{T0}"/> that may be in a success or failed state.</returns>
        public static async Task<Result<TO>> BindAsync<TI, TO>(
            this Task<Result<TI>> resultTask,
            Func<TI, Task<Result<TO>>> func) {
            var result = await resultTask;
            return !result.IsSuccess ? Result<TO>.Fail(result.Error) : await func(result.Value);
        }
        
        /// <summary>
        /// Used to transform the underlying data type if the result is a success. 
        /// </summary>
        /// <param name="result">The incoming result.</param>
        /// <param name="map">The method used to transform the underlying type.</param>
        /// <typeparam name="TI">The incoming type param.</typeparam>
        /// <typeparam name="TO">The outgoing type param.</typeparam>
        /// <returns>A <see cref="Result{TO}"/> that may be in a success or failed state.</returns>
        public static Result<TO> Map<TI, TO>(
            this Result<TI> result,
            Func<TI, TO> map) => !result.IsSuccess ? Result<TO>.Fail(result.Error) : Result<TO>.Ok(map(result.Value));

        /// <summary>
        /// An asynchronous version of Map used to transform the underlying data type if hte result is a success.
        /// </summary>
        /// <param name="resultTask">The incoming result task that can be run.</param>
        /// <param name="map">The method used to transform the underlying type.</param>
        /// <typeparam name="TI">The incoming type param.</typeparam>
        /// <typeparam name="TO">The outgoing type param.</typeparam>
        /// <returns>A <see cref="Result{TO}"/> that may be in a success or failed state.</returns>
        public static async Task<Result<TO>> MapAsync<TI, TO>(
            this Task<Result<TI>> resultTask,
            Func<TI, TO> map) {
            var result = await resultTask;
            return !result.IsSuccess ? Result<TO>.Fail(result.Error) : Result<TO>.Ok(map(result.Value));
        }

        /// <summary>
        /// Tries to run a passed method, and if an exception is thrown, a Result Failure is returned.
        /// </summary>
        /// <param name="func">The method that is run.</param>
        /// <typeparam name="T">The return type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> of the return of the supplied method.</returns>
        public static Result<T> Try<T>(Func<T> func) {
            try {
                return Result<T>.Ok(func());
            }
            catch (Exception ex) {
                return Result<T>.Fail(ex.Message);
            }
        }

        /// <summary>
        /// An asynchronous version of Try used to run a passed method. If an exception is thrown a Result Failure is returned.
        /// </summary>
        /// <param name="func">The method that is run.</param>
        /// <typeparam name="T">The return type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> of the return of the supplied method.</returns>
        public static async Task<Result<T>> TryAsync<T>(Func<Task<T>> func) {
            try {
                return Result<T>.Ok(await func());
            }
            catch (Exception ex) {
                return Result<T>.Fail(ex.Message);
            }
        }

        /// <summary>
        /// A method used to run multiple result methods in parallel. Returns a tuple of the return types of the combined
        /// methods. If chained will return a nested tuple.
        /// </summary>
        /// <param name="first">The first method to run.</param>
        /// <param name="second">The second method to run.</param>
        /// <typeparam name="T1">The return type of the first method.</typeparam>
        /// <typeparam name="T2">The return type of the second method.</typeparam>
        /// <returns>A <see cref="Result{T}"/> with a tuple of the types of that are passed in.</returns>
        public static Result<(T1, T2)> Combine<T1, T2>(
            this Result<T1> first,
            Result<T2> second) {
            if (first.IsSuccess && second.IsSuccess) {
                return Result<(T1, T2)>.Ok((first.Value, second.Value));
            }

            var allErrors = new List<string>();
            if (!first.IsSuccess) allErrors.AddRange(first.Errors);
            if (!second.IsSuccess) allErrors.AddRange(first.Errors);
            return Result<(T1, T2)>.Fail(allErrors);
        }

        /// <summary>
        /// The asynchronous version of Combine. Is used to run multiple result methods in parallel. Returns a tuple of
        /// return types of the combined methods. If chained will return a nested tuple.
        /// </summary>
        /// <param name="first">The first method to run.</param>
        /// <param name="second">The second method to run.</param>
        /// <typeparam name="T1">The return type of the first method.</typeparam>
        /// <typeparam name="T2">The return type of the second method.</typeparam>
        /// <returns>A <see cref="Result{T}"/> with a tuple of the types that are passed in.</returns>
        public static async Task<Result<(T1, T2)>> CombineAsync<T1, T2>(
            Task<Result<T1>> first,
            Task<Result<T2>> second) {
            await Task.WhenAll(first, second);
            
            var r1 = await first;
            var r2 = await second;

            if (r1.IsSuccess && r2.IsSuccess) 
                return Result<(T1, T2)>.Ok((r1.Value, r2.Value));

            var errors = new List<string>();
            if (!r1.IsSuccess) errors.AddRange(r1.Errors);
            if (!r2.IsSuccess) errors.AddRange(r2.Errors);
            return Result<(T1, T2)>.Fail(errors);
        }

        /// <summary>
        /// A method that is used to run multiple result functions and combine the results in a way that does not lead
        /// nested tuples. This is used to implement partial application. Does not short circuit if an error occurs in
        /// the chain.
        /// </summary>
        /// <param name="rf">The result function that is run.</param>
        /// <param name="rt">The result value that is output from the following method in the chain.</param>
        /// <typeparam name="TI">The input type param.</typeparam>
        /// <typeparam name="TO">The output type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> of the final output.</returns>
        public static Result<TO> Apply<TI, TO>(
            this Result<Func<TI, TO>> rf,
            Result<TI> rt) {
            if (rf.IsSuccess && rt.IsSuccess) 
                return Result<TO>.Ok(rf.Value(rt.Value));
            
            var errors = new List<string>();
            if (!rf.IsSuccess) errors.AddRange(rf.Errors);
            if (!rt.IsSuccess) errors.AddRange(rf.Errors);
            
            return Result<TO>.Fail(errors);
        }

        /// <summary>
        /// The asynchronous version of Apply. A method that is ued to run multiple result functions and combine the
        /// results in a way that does not return nested tuples.  This is used to implement partial application. Does
        /// not short circuit if an error occurs in the chain.
        /// </summary>
        /// <param name="rfTask">The task of the result function that is run.</param>
        /// <param name="rtTask">The result value that is output from the following method in the chain.</param>
        /// <typeparam name="TI">The input type param.</typeparam>
        /// <typeparam name="TO">The output type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> of the final output.</returns>
        public static async Task<Result<TO>> ApplyAsync<TI, TO>(
            this Task<Result<Func<TI, TO>>> rfTask,
            Task<Result<TI>> rtTask) {
            await Task.WhenAll(rfTask, rtTask);
            var rf = await rfTask;
            var rt = await rtTask;
            
            if (rf.IsSuccess && rt.IsSuccess)
                return Result<TO>.Ok(rf.Value(rt.Value));
            
            var errors = new List<string>();
            if (!rf.IsSuccess) errors.AddRange(rf.Errors);
            if (!rt.IsSuccess) errors.AddRange(rf.Errors);
            return Result<TO>.Fail(errors);
        }
        
        
        // The following methods are used to handle Linq functionality
        
        /// <summary>
        /// Used to transform the underlying data type if the result is a success. May also be referred to as a map.
        /// </summary>
        /// <param name="result">The incoming result.</param>
        /// <param name="selector">The method used to transform the underlying type.</param>
        /// <typeparam name="TI">The incoming type param.</typeparam>
        /// <typeparam name="TO">The outgoing type param.</typeparam>
        /// <returns>A <see cref="Result{TO}"/> that may be in a success or failed state.</returns>
        public static Result<TO> Select<TI, TO>(
            this Result<TI> result,
            Func<TI, TO> selector) =>  result.Map(selector);
            
        /// <summary>
        /// An asynchronous version of Select used to transform the underlying data type if hte result is a success.
        /// May also be referred to as a map.
        /// </summary>
        /// <param name="resultTask">The incoming result task that can be run.</param>
        /// <param name="selector">The method used to transform the underlying type.</param>
        /// <typeparam name="TI">The incoming type param.</typeparam>
        /// <typeparam name="TO">The outgoing type param.</typeparam>
        /// <returns>A <see cref="Result{TO}"/> that may be in a success or failed state.</returns>
        public static Task<Result<TO>> Select<TI, TO>(
            this Task<Result<TI>> resultTask,
            Func<TI, TO> selector) => resultTask.MapAsync(selector);
        
        /// <summary>
        /// Used to bind a method to a new result type. May also be referred to as Bind.
        /// </summary>
        /// <param name="result">The previous result that is used to bind to the chain.</param>
        /// <param name="func">The method to bind to.</param>
        /// <typeparam name="TI">The input type param.</typeparam>
        /// <typeparam name="TO">The output type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> that may be in a success or failed state.</returns>
        public static Result<TO> SelectMany<TI, TO>(
            this Result<TI> result,
            Func<TI, Result<TO>> func) => result.Bind(func);

        /// <summary>
        /// A select and projection of a result. Calls a Bind => Map. At times referred to as a FlatMap.
        /// </summary>
        /// <param name="source">The source Result to start the action.</param>
        /// <param name="binder">The Bind method to run the result through.</param>
        /// <param name="resultSelector">The final projection used to map the results.</param>
        /// <typeparam name="TI1">The first incoming type param.</typeparam>
        /// <typeparam name="TI2">The second incoming type param.</typeparam>
        /// <typeparam name="TO">The output type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> that may be in a success or failed state.</returns>
        public static Result<TO> SelectMany<TI1, TI2, TO>(
            this Result<TI1> source,
            Func<TI1, Result<TI2>> binder,
            Func<TI1, TI2, TO> resultSelector) => source.Bind(i1 => binder(i1).Map(i2 => resultSelector(i1, i2)));

        /// <summary>
        /// The asynchronous version of the SelectMany that is a wrapper on Bind.
        /// </summary>
        /// <param name="resultTask">The previous result that is used to bind to the chain.</param>
        /// <param name="binder">The method to bind to.</param>
        /// <typeparam name="TI">The input type param.</typeparam>
        /// <typeparam name="TO">The output type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> that may be in a success or failed state.</returns>
        public static Task<Result<TO>> SelectMany<TI, TO>(
            this Task<Result<TI>> resultTask,
            Func<TI, Task<Result<TO>>> binder) => resultTask.BindAsync(binder);

        /// <summary>
        /// The asynchronous version of select and project of a result. Calls BindAsync => MapAsync. At times referred
        /// to as FlatMap.
        /// </summary>
        /// <param name="sourceTask">The source result to start the action.</param>
        /// <param name="binder">The Bind method to run the result through.</param>
        /// <param name="resultSelector">The final projection used to map the results.</param>
        /// <typeparam name="TI1">The first incoming type param.</typeparam>
        /// <typeparam name="TI2">The second incoming type param.</typeparam>
        /// <typeparam name="TO">The output type param.</typeparam>
        /// <returns>A <see cref="Result{T}"/> that may be in a success or failed state.</returns>
        public static Task<Result<TO>> SelectMany<TI1, TI2, TO>(
            this Task<Result<TI1>> sourceTask,
            Func<TI1, Task<Result<TI2>>> binder,
            Func<TI1, TI2, TO> resultSelector) => sourceTask.BindAsync(i1 => binder(i1).MapAsync(i2 => resultSelector(i1, i2))); 
    }

    public class Result<T> : Result {
        public T Value { get; set; }
    
        protected Result(T value, bool success, string error) : base(success, error) {
            Value = value;
        }

        protected Result(T value, bool success, IEnumerable<string> errors) : base(success, errors) {
            Value = value;
        }

        public new static Result<T> Fail(string message) {
            return new Result<T>(default, false, message);
        }

        public new static Result<T> Fail(IEnumerable<string> errors) {
            return new Result<T>(default, false, errors);
        }
    
        public static Result<T> Fail() {
            return new Result<T>(default, false, string.Empty);
        }

        public static Result<T> Ok(T value) {
            return new Result<T>(value, true, string.Empty);
        }
    }

    public class Result {

        public IEnumerable<string> Errors { get; set; } = [];
        public string Error { get; set; }
        public bool IsSuccess => string.IsNullOrWhiteSpace(Error) && Success;
        private bool Success { get; set; }

        protected Result(bool success, string error) {
            Success = success;
            Error = error;
        }

        protected Result(bool success, IEnumerable<string> errors) {
            Success = success;
            Errors = errors;
        }

        public static Result Fail(string message) {
            return new Result(false, message);
        }

        public static Result Fail(IEnumerable<string> errors) {
            return new Result(false, errors);
        }

        public static Result Ok() {
            return new Result(true, string.Empty);
        }
    }
}
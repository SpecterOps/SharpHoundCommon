#nullable enable

using System;
using System.Collections.Generic;

namespace SharpHoundRPC.Registry {

    public class StrategyExecutorResult<T> {
        public IEnumerable<T>? Results { get; set; } = null;
        public IEnumerable<StrategyResult<T>>? FailureAttempts { get; set; } = null;
        public bool WasSuccessful = false;
        public Type? SuccessfulStrategy { get; set; } = null;
    }
}

#nullable disable
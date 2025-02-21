namespace SharpHoundCommonLib.OutputTypes {
    public class APIResult {
        public bool Collected { get; set; }
        public string FailureReason { get; set; }
    }

    public class APIResult<T> : APIResult {
        public T Result { get; set; }

        public static APIResult<T> Success(T result) {
            return new APIResult<T> {
                Result = result,
                Collected = true
            };
        }

        public static APIResult<T> Failure(string failureReason) {
            return new APIResult<T> {
                Collected = false,
                FailureReason = failureReason
            };
        }
        
        public static implicit operator APIResult<T>(T input)
        {
            return Success(input);
        }
    }
}
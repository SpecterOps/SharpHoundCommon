namespace SharpHoundCommonLib {
    public class Result<T> : Result {
        public T Value { get; set; }
    
        protected Result(T value, bool success, string error) : base(success, error) {
            Value = value;
        }

        public new static Result<T> Fail(string message) {
            return new Result<T>(default, false, message);
        }
    
        public static Result<T> Fail() {
            return new Result<T>(default, false, string.Empty);
        }

        public static Result<T> Ok(T value) {
            return new Result<T>(value, true, string.Empty);
        }
    }

    public class Result {
    
        public string Error { get; set; }
        public bool IsSuccess => string.IsNullOrWhiteSpace(Error) && Success;
        private bool Success { get; set; }

        protected Result(bool success, string error) {
            Success = success;
            Error = error;
        }

        public static Result Fail(string message) {
            return new Result(false, message);
        }

        public static Result Ok() {
            return new Result(true, string.Empty);
        }
    }
}
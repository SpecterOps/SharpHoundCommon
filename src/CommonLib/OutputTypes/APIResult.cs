namespace SharpHoundCommonLib.OutputTypes
{
    public class BaseAPIResult<T>
    {
        public bool Collected { get; set; }
        public string FailureReason { get; set; }
    }

#nullable enable
    public class APIResult
    {
        public bool Collected { get; set; }
        public string? FailureReason { get; set; }
    }
    public class ApiResult<T> : APIResult
    {
        public T? Results { get; set; }

        public ApiResult()
        {
            Results = default(T);
            Collected = false;
            FailureReason = null;
        }

        public ApiResult(T? data)
        {
            Results = data;
            Collected = data != null;
            FailureReason = null;
        }

        public static ApiResult<T> CreateSuccess(T result)
        {
            return new ApiResult<T>(result)
            {
                Collected = true,
                FailureReason = null
            };
        }

        public static ApiResult<T> CreateError(string message)
        {
            return new ApiResult<T>(default)
            {
                Collected = false,
                FailureReason = message
            };
        }
    }
#nullable disable
}
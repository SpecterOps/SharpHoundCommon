using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundRPC
{
    public static class Extensions
    {
        public static bool IsError(this NtStatus status)
        {
            if (status != NtStatus.StatusSuccess && status != NtStatus.StatusMoreEntries &&
                status != NtStatus.StatusSomeMapped && status != NtStatus.StatusNoMoreEntries)
                return true;

            return false;
        }

        /// <summary>
        ///     Gets the relative identifier for a SID
        /// </summary>
        /// <param name="securityIdentifier"></param>
        /// <returns></returns>
        public static int Rid(this SecurityIdentifier securityIdentifier)
        {
            var value = securityIdentifier.Value;
            var rid = int.Parse(value.Substring(value.LastIndexOf("-", StringComparison.Ordinal) + 1));
            return rid;
        }

        public static byte[] GetBytes(this SecurityIdentifier identifier)
        {
            var bytes = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(bytes, 0);
            return bytes;
        }
        
        public static async Task<Result<T>> TimeoutAfter<T>(this Task<Result<T>> task, TimeSpan timeout) {

            using (var timeoutCancellationTokenSource = new CancellationTokenSource()) {

                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token));
                if (completedTask == task) {
                    timeoutCancellationTokenSource.Cancel();
                    return await task; // Very important in order to propagate exceptions
                }

                var result = Result<T>.Fail("Timeout");
                result.IsTimeout = true;
                return result;
            }
        }
        
        public static async Task<NetAPIResult<T>> TimeoutAfter<T>(this Task<NetAPIResult<T>> task, TimeSpan timeout) {

            using (var timeoutCancellationTokenSource = new CancellationTokenSource()) {

                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token));
                if (completedTask == task) {
                    timeoutCancellationTokenSource.Cancel();
                    return await task; // Very important in order to propagate exceptions
                }

                var result = NetAPIResult<T>.Fail("Timeout");
                return result;
            }
        }
    }
}
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
    }
}
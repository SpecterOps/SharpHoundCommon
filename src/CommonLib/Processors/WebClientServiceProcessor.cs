using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using SharpHoundCommonLib.OutputTypes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors {
    public class WebClientServiceProcessor(ILogger log = null) {
        private readonly ILogger _log = log ?? Logging.LogProvider.CreateLogger("WebClientServiceProcessor");

        // Define constants
        public const uint MAXIMUM_ALLOWED = 0x02000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint OPEN_EXISTING = 3;

        // Error constants
        public const uint ERROR_FILE_NOT_FOUND = 0x80070002;
        public const uint ERROR_ACCESS_DENIED = 0x80070005;
        public const uint ERROR_BAD_NETPATH = 0x80070035;
        public const uint ERROR_NETNAME_DELETED = 0x80070040;
        public const uint ERROR_NETWORK_ACCESS_DENIED = 0x80070041;
        public const uint ERROR_LOGON_FAILURE = 0x8007052E;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        public static bool TestPathExists(string path) {
            using var handle = CreateFile(
                path,
                MAXIMUM_ALLOWED, // Request maximum allowed access
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // Allow all share modes
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero
            );

            var result = Marshal.GetHRForLastWin32Error();

            if (handle.IsInvalid) {
                switch ((uint)result) {
                    case ERROR_ACCESS_DENIED:
                        return true;
                    case ERROR_BAD_NETPATH:
                    case ERROR_FILE_NOT_FOUND:
                    case ERROR_NETNAME_DELETED:
                    case ERROR_NETWORK_ACCESS_DENIED:
                        return false;
                    default:
                        Marshal.ThrowExceptionForHR(result);
                        break;
                }
            }

            return true;
        }

        public async Task<ApiResult<bool>> IsWebClientRunning(string computerName) {
            // When the service is running, this named pipe is present
            var pipePath = @$"\\{computerName}\pipe\DAV RPC SERVICE";

            return await Task.Run(() => {
                try {
                    var exists = TestPathExists(pipePath);

                    return ApiResult<bool>.CreateSuccess(exists);
                } catch (Exception ex) {
                    return ApiResult<bool>.CreateError(ex.ToString());
                }
            });
        }
    }
}
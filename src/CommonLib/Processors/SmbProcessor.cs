using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;
using System;
using System.Collections.Specialized;
using System.Threading.Tasks;
using SharpHoundRPC;
using SharpHoundCommonLib.SMB;

namespace SharpHoundCommonLib.Processors {
    /// <summary>
    /// This processor implements the SMB negotation process in order to retrieve several info about SMB from a host, notable whether NTLM signing is required.
    /// </summary>
    /// <param name="timeoutMs"></param>
    /// <param name="log"></param>
    public class SmbProcessor
    {
        //TODO: Have this class take in our portscanner class and use that
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);
        private readonly ILogger _log;
        private readonly ISmbScanner _smbScanner;
        private readonly int _timeoutMs;
        
        public SmbProcessor(int timeoutMs, ISmbScanner smbScanner = null, ILogger log = null)
        {
            _timeoutMs = timeoutMs;
            _smbScanner = smbScanner ?? new SmbScanner(_log) { TimeoutMs = _timeoutMs };
            _log = log ?? Logging.LogProvider.CreateLogger("SmbProcessor");
        }

        public event ComputerStatusDelegate ComputerStatusEvent;
        public virtual async Task<APIResult<SmbInfo>> Scan(string host, TimeSpan timeout = default) {
            if (timeout == default) {
                timeout = TimeSpan.FromMinutes(2);
            }

            var result = await Task.Run(() => _smbScanner.ScanHost(host, 445)).TimeoutAfter(timeout);

            if (result.IsFailed) {
                await SendComputerStatus(new CSVComputerStatus {
                    Status = result.Error,
                    Task = "SmbScan",
                    ComputerName = host
                });
                _log.LogTrace("SmbScan failed on {ComputerName}: {Status}", host, result.Error);
                return APIResult<SmbInfo>.Failure(result.Error);
            }

            if (result.Value == null)
            {
                await SendComputerStatus(new CSVComputerStatus {
                    Status = result.Error ?? "Unknown error",
                    Task = "SmbScan",
                    ComputerName = host
                });
                _log.LogTrace("SmbScan failed on {ComputerName} - null result: {Status}", host, result.Status);
                return APIResult<SmbInfo>.Failure(result.Error ?? "Unknown error");
            }
            
            _log.LogDebug("SmbScan succeeded on {ComputerName}", host);
            await SendComputerStatus(new CSVComputerStatus {
                Status = CSVComputerStatus.StatusSuccess,
                Task = "SmbScan",
                ComputerName = host
            });
            
            var info = new SmbInfo() {
                SigningEnabled = result.Value.SigningRequired
            };

            return APIResult<SmbInfo>.Success(info);

        }
        
        private async Task SendComputerStatus(CSVComputerStatus status) {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
        }
    }

    public enum SmbVersion {
        Unknown,
        SMBv1,
        SMBv2
    }

    public class SmbScanInfo {
        public SmbScanInfo(string host) {
            Host = host;
        }

        public string Host { get; set; }
        public bool SigningRequired { get; set; }
    }
}

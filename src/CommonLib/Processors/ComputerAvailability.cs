using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerAvailability
    {
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

        private readonly int _computerExpiryDays;
        private readonly ILogger _log;
        private readonly PortScanner _scanner;
        private readonly int _scanTimeout;
        private readonly bool _skipPasswordCheck;
        private readonly bool _skipPortScan;

        public ComputerAvailability(int timeout = 10000, int computerExpiryDays = 60, bool skipPortScan = false,
            bool skipPasswordCheck = false, ILogger log = null)
        {
            _scanner = new PortScanner();
            _scanTimeout = timeout;
            _skipPortScan = skipPortScan;
            _log = log ?? Logging.LogProvider.CreateLogger("CompAvail");
            _computerExpiryDays = computerExpiryDays;
            _skipPasswordCheck = skipPasswordCheck;
        }

        public ComputerAvailability(PortScanner scanner, int timeout = 500, int computerExpiryDays = 60,
            bool skipPortScan = false, bool skipPasswordCheck = false,
            ILogger log = null)
        {
            _scanner = scanner;
            _scanTimeout = timeout;
            _skipPortScan = skipPortScan;
            _log = log ?? Logging.LogProvider.CreateLogger("CompAvail");
            _computerExpiryDays = computerExpiryDays;
            _skipPasswordCheck = skipPasswordCheck;
        }

        public event ComputerStatusDelegate ComputerStatusEvent;

        /// <summary>
        ///     Helper function to use commonlib types for IsComputerAvailable
        /// </summary>
        /// <param name="result"></param>
        /// <param name="entry"></param>
        /// <returns></returns>
        public Task<ComputerStatus> IsComputerAvailable(ResolvedSearchResult result, IDirectoryObject entry)
        {
            var name = result.DisplayName;
            var os = entry.GetProperty(LDAPProperties.OperatingSystem);
            var pwdlastset = entry.GetProperty(LDAPProperties.PasswordLastSet);
            var lastLogon = entry.GetProperty(LDAPProperties.LastLogonTimestamp);
            
            return IsComputerAvailable(name, os, pwdlastset, lastLogon);
        }

        /// <summary>
        ///     Checks if a computer is available for SharpHound enumeration using the following criteria:
        ///     The "operatingsystem" LDAP attribute must contain the string "Windows"
        ///     The "pwdlastset" LDAP attribute must be within 60 days of the current date by default.
        ///     Port 445 must be open to allow API calls to succeed
        /// </summary>
        /// <param name="computerName">The computer to check availability for</param>
        /// <param name="operatingSystem">The LDAP operatingsystem attribute value</param>
        /// <param name="pwdLastSet">The LDAP pwdlastset attribute value</param>
        /// <param name="lastLogon">The LDAP lastlogontimestamp attribute value</param>
        /// <returns>A <cref>ComputerStatus</cref> object that represents the availability of the computer</returns>
        public async Task<ComputerStatus> IsComputerAvailable(string computerName, string operatingSystem,
            string pwdLastSet, string lastLogon)
        {
            if (operatingSystem != null && !operatingSystem.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
            {
                _log.LogTrace("{ComputerName} is not available because operating system {OperatingSystem} is not valid",
                    computerName, operatingSystem);
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = ComputerStatus.NonWindowsOS,
                    Task = "ComputerAvailability",
                    ComputerName = computerName
                });
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.NonWindowsOS
                };
            }

            if (!_skipPasswordCheck && !IsComputerActive(pwdLastSet, lastLogon))
            {
                _log.LogTrace(
                    "{ComputerName} is not available because password last set and lastlogontimestamp are out of range",
                    computerName);
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = ComputerStatus.NotActive,
                    Task = "ComputerAvailability",
                    ComputerName = computerName
                });
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.NotActive
                };
            }

            if (_skipPortScan)
                return new ComputerStatus
                {
                    Connectable = true,
                    Error = null
                };

            if (!await _scanner.CheckPort(computerName, 445))
            {
                _log.LogTrace("{ComputerName} is not available because port 445 is unavailable", computerName);
                await SendComputerStatus(new CSVComputerStatus
                {
                    Status = ComputerStatus.PortNotOpen,
                    Task = "ComputerAvailability",
                    ComputerName = computerName
                });
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.PortNotOpen
                };
            }

            _log.LogTrace("{ComputerName} is available for enumeration", computerName);

            await SendComputerStatus(new CSVComputerStatus
            {
                Status = CSVComputerStatus.StatusSuccess,
                Task = "ComputerAvailability",
                ComputerName = computerName
            });

            return new ComputerStatus
            {
                Connectable = true,
                Error = null
            };
        }

        /// <summary>
        /// Checks if a computer's passwordlastset/lastlogontimestamp attributes are within a certain range
        /// </summary>
        /// <param name="pwdLastSet"></param>
        /// <param name="lastLogonTimestamp"></param>
        /// <returns></returns>
        private bool IsComputerActive(string pwdLastSet, string lastLogonTimestamp) {
            var passwordLastSet = Helpers.ConvertLdapTimeToLong(pwdLastSet);
            var lastLogonTimeStamp = Helpers.ConvertLdapTimeToLong(lastLogonTimestamp);
            var threshold = DateTime.Now.AddDays(_computerExpiryDays * -1).ToFileTimeUtc();

            return passwordLastSet >= threshold || lastLogonTimeStamp >= threshold;
        }

        private async Task SendComputerStatus(CSVComputerStatus status)
        {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
        }
    }
}
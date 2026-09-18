using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using SharpHoundRPC.Handles;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public class SAMServer : SAMBase, ISAMServer
    {
        private readonly ConcurrentDictionary<string, SAMDomain> _domainHandleCache;
        private SecurityIdentifier _cachedMachineSid;

        public SAMServer(SAMHandle handle, string computerName) : base(handle)
        {
            _domainHandleCache = new ConcurrentDictionary<string, SAMDomain>();
            ComputerName = computerName;
        }

        public string ComputerName { get; }

        public Result<IEnumerable<(string Name, int Rid)>> GetDomains()
        {
            var (status, rids, count) = SAMMethods.SamEnumerateDomainsInSamServer(Handle);
            if (status.IsError()) return status;

            var ret = Result<IEnumerable<(string Name, int Rid)>>.Ok(rids
                .GetEnumerable<SAMStructs.SamRidEnumeration>(count).Select(x => (x.Name.ToString(), x.Rid)));
            return ret;
        }

        public Result<SecurityIdentifier> LookupDomain(string name)
        {
            var (status, sid) = SAMMethods.SamLookupDomainInSamServer(Handle, name);
            using (sid)
            {
                return status.IsError() ? status : sid.GetData<SecurityIdentifier>();
            }
        }

        public Result<SecurityIdentifier> GetMachineSid(string testName = null, CancellationToken cancellationToken = default)
        {
            if (_cachedMachineSid != null)
                return _cachedMachineSid;

            cancellationToken.ThrowIfCancellationRequested();

            SecurityIdentifier sid = null;

            if (testName != null)
            {
                var result = LookupDomain(testName);
                if (result.IsSuccess) sid = result.Value;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (sid == null)
            {
                var domainResult = GetDomains();
                cancellationToken.ThrowIfCancellationRequested();
                if (domainResult.IsSuccess)
                {
                    var result = LookupDomain(domainResult.Value.FirstOrDefault().Name);
                    if (result.IsSuccess) sid = result.Value;
                }
            }

            if (sid == null) return "Unable to get machine sid";
            _cachedMachineSid = sid;
            return sid;
        }

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalBySid(
            SecurityIdentifier securityIdentifier,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var openDomainResult = OpenDomain(securityIdentifier);
            if (openDomainResult.IsFailed) return $"OpenDomain returned {openDomainResult.Status}";

            var domain = openDomainResult.Value;

            cancellationToken.ThrowIfCancellationRequested();

            return domain.LookupPrincipalByRid(securityIdentifier.Rid());
        }

        public Result<ISAMDomain> OpenDomain(string domainName, SAMEnums.DomainAccessMask requestedDomainAccess =
            SAMEnums.DomainAccessMask.Lookup |
            SAMEnums.DomainAccessMask.ListAccounts,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var lookupResult = LookupDomain(domainName);
            if (lookupResult.IsFailed) return $"LookupDomain returned {lookupResult.Error}";

            var sid = lookupResult.Value;

            if (_domainHandleCache.TryGetValue(sid.Value, out var domain)) return domain;

            cancellationToken.ThrowIfCancellationRequested();

            var (status, domainHandle) = SAMMethods.SamOpenDomain(Handle, requestedDomainAccess, sid.GetBytes());
            if (status.IsError()) return status;

            domain = new SAMDomain(domainHandle);

            _domainHandleCache.TryAdd(sid.Value, domain);
            return domain;
        }

        public Result<ISAMDomain> OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess =
                SAMEnums.DomainAccessMask.Lookup |
                SAMEnums.DomainAccessMask.ListAccounts)
        {
            if (_domainHandleCache.TryGetValue(securityIdentifier.Value, out var domain)) return domain;

            var (status, domainHandle) =
                SAMMethods.SamOpenDomain(Handle, requestedDomainAccess, securityIdentifier.GetBytes());
            if (status.IsError()) return status.ToString();

            domain = new SAMDomain(domainHandle);
            _domainHandleCache.TryAdd(securityIdentifier.Value, domain);
            return domain;
        }

        protected override void Dispose(bool disposing)
        {
            foreach (var domainHandle in _domainHandleCache.Values) domainHandle.Dispose();
            base.Dispose(disposing);
        }
    }
}
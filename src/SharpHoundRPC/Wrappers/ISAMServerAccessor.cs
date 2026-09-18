using SharpHoundRPC.SAMRPCNative;

namespace SharpHoundRPC.Wrappers
{
    public interface ISAMServerAccessor
    {
        Result<ISAMServer> OpenServer(string computerName, SAMEnums.SamAccessMasks requestedConnectAccess =
            SAMEnums.SamAccessMasks.SamServerConnect |
            SAMEnums.SamAccessMasks.SamServerEnumerateDomains |
            SAMEnums.SamAccessMasks.SamServerLookupDomain);
    }

    public class SAMServerAccessor : ISAMServerAccessor
    {
        public Result<ISAMServer> OpenServer(string computerName, SAMEnums.SamAccessMasks requestedConnectAccess =
            SAMEnums.SamAccessMasks.SamServerConnect |
            SAMEnums.SamAccessMasks.SamServerEnumerateDomains |
            SAMEnums.SamAccessMasks.SamServerLookupDomain)
        {
            var (status, handle) = SAMMethods.SamConnect(computerName, requestedConnectAccess);

            return status.IsError()
                ? status
                : new SAMServer(handle, computerName);
        }
    }
}
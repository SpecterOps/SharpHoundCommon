#nullable enable
using SharpHoundRPC.Registry;

namespace SharpHoundCommonLib.OutputTypes;

public class RegistryData
{
    public uint? RestrictSendingNtlmTraffic { get; set; } = null;
    public uint? RestrictReceivingNtlmTraffic { get; set; } = null;
    public uint? NtlmMinServerSec { get; set; } = null;
    public uint? NtlmMinClientSec { get; set; } = null;
    public uint? LmCompatibilityLevel { get; set; } = null;
    public uint? UseMachine { get; set; } = null;
}
#nullable disable
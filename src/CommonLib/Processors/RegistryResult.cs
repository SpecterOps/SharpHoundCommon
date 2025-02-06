using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.OutputTypes.APIResult;

namespace SharpHoundCommonLib.Processors {
    public class RegistryResult : APIResult {
        public object Value { get; set; }
    }
}
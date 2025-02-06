using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class LSAPrivilegeAPIResult : APIResult.APIResult
    {
        public TypedPrincipal[] Results { get; set; } = Array.Empty<TypedPrincipal>();
    }
}
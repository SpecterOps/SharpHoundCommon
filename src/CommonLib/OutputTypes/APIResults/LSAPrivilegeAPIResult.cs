using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class LSAPrivilegeAPIResult : APIResult
    {
        public TypedPrincipal[] Results { get; set; } = Array.Empty<TypedPrincipal>();
    }
}
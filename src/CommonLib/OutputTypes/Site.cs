using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Site : OutputBase
    {
        // Subnets and Servers are common site children; keep them optional and empty by default.
        //public string[] Subnets { get; set; } = Array.Empty<string>();
        //public TypedPrincipal[] Servers { get; set; } = Array.Empty<TypedPrincipal>();
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
    }
}
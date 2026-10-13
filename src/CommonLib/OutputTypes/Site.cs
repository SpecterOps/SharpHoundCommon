using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Site : OutputBase
    {
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
        public string[] InheritanceHashes { get; set; } = Array.Empty<string>();
    }
}

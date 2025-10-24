using System;
using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes
{
    public class ResultingGPOUserRights
    {
        public TypedPrincipal[] AffectedComputers { get; set; } = Array.Empty<TypedPrincipal>();

        // Dictionary mapping privilege name to array of principals that have that privilege
        public Dictionary<string, TypedPrincipal[]> UserRightAssignments { get; set; } =
            new Dictionary<string, TypedPrincipal[]>();
    }
}
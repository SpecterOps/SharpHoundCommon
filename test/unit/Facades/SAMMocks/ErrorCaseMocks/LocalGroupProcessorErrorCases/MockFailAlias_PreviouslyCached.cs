using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class MockFailAlias_PreviouslyCached : ISAMAlias
    {
        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            return new List<SecurityIdentifier>()
            {
                new("S-1-5-21-321011808-3761883066-353627080-1003"),
                new("S-1-5-21-321011808-3761883066-353627080-1003"),
                new("S-1-5-32-544"),
            };
        }

        public void Dispose()
        {
            throw new System.NotImplementedException();
        }
    }
}
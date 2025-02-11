using System;
using System.Text;

namespace SharpHoundCommonLib.OutputTypes
{
    public class LocalGroupAPIResult : APIResult
    {
        public string ObjectIdentifier { get; set; }
        public string Name { get; set; }
        public TypedPrincipal[] Results { get; set; } = Array.Empty<TypedPrincipal>();
        public NamedPrincipal[] LocalNames { get; set; } = Array.Empty<NamedPrincipal>();

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.AppendLine($"Local group {Name} ({ObjectIdentifier})");
            foreach (var x in Results) builder.AppendLine(x.ToString());

            builder.AppendLine("Extra Names:");

            foreach (var x in LocalNames) builder.AppendLine(x.ToString());
            return builder.ToString();
        }
    }
}
namespace SharpHoundCommonLib.OutputTypes
{
    public class IssuancePolicy : OutputBase
    {
        public TypedPrincipal GroupLink { get; set; } = new();
    }
}
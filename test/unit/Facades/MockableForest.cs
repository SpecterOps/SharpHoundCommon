using System.DirectoryServices.ActiveDirectory;

namespace CommonLibTest.Facades
{
    public class MockableForest
    {
        public static Forest Construct(string forestDnsName)
        {
            var forest = FacadeHelpers.GetUninitializedObject<Forest>();
            FacadeHelpers.SetField(forest, "_forestDnsName", forestDnsName);

            return forest;
        }
    }
}
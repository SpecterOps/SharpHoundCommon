using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using SharpHoundCommonLib;
using BindingFlags = System.Reflection.BindingFlags;

namespace CommonLibTest.Facades
{
    public class MockableSearchResultEntry
    {
        public static SearchResultEntry Construct(Dictionary<string, object> values, string distinguishedName)
        {
            var attributes = CreateAttributes(values);

            return CreateSearchResultEntry(attributes, distinguishedName);
        }


        private static SearchResultAttributeCollection CreateAttributes(Dictionary<string, object> values)
        {
            var coll =
                (SearchResultAttributeCollection)typeof(SearchResultAttributeCollection)
                    .GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, Type.EmptyTypes, null)
                    .Invoke(null);

            var dict = (IDictionary) typeof(SearchResultAttributeCollection).GetProperty("Dictionary",
                BindingFlags.NonPublic | BindingFlags.Instance).GetValue(coll);
            
            foreach (var v in values)
            {
                dict.Add(v.Key, new DirectoryAttribute(v.Key, v.Value));
            }
            return coll;
        }

        private static SearchResultEntry CreateSearchResultEntry(SearchResultAttributeCollection attributes,
            string distinguishedName)
        {
            var types = new[]
            {
                typeof(string),
                typeof(SearchResultAttributeCollection),
            };
            
            var sre = (SearchResultEntry)typeof(SearchResultEntry)
                .GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, types, null)
                .Invoke(new object[]{ distinguishedName, attributes});

            return sre;
        }
    }
}
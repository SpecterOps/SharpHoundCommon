using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class WebClientServiceProcessorTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;

        public WebClientServiceProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }
    
        [WindowsOnlyFact]
        public async Task WebClientServiceProcessorTest_TestPathExists()
        {
            var processor = new WebClientServiceProcessor();
            
            var result = await processor.IsWebClientRunning("primary.testlab.local");
            
            Assert.True(result.Collected);
            Assert.False(result.Result);
        }
        
    }
}
using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using Moq;

namespace CommonLibTest.Facades;

public static class MockExtentions
{
    public static void VerifyLogContains<T>(this Mock<ILogger<T>> mockLogger, LogLevel logLevel, params string[] expected)
    {
        mockLogger.Verify(
            x => x.Log(
                logLevel,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) =>
                    expected.All(s => o.ToString().Contains(s, StringComparison.OrdinalIgnoreCase))),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
    
    public static void VerifyLog<T>(this Mock<ILogger<T>> mockLogger, LogLevel logLevel, string expectedMessage)
    {
        mockLogger.Verify(
            x => x.Log(
                logLevel,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) =>
                    string.Equals(expectedMessage, o.ToString(), StringComparison.InvariantCultureIgnoreCase)),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}
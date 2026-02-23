using SharpHoundRPC.Registry;
using Xunit;

namespace RPCTest.Registry;

public class StrategyExecutorTests {
    private readonly StrategyExecutor _strategyExecutor = new();
    
    [Fact]
    public async Task CollectAsync_NoStrategies_ReturnsFailure_WithNoAttempts() {
        // Act
        var result = await _strategyExecutor.CollectAsync<RegistryQueryResult, RegistryQuery>("target machine", [], []);
        
        // Assert
        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Empty(result.FailureAttempts!);
        Assert.Null(result.Results);
        Assert.Null(result.SuccessfulStrategy);
    }
    
    [Fact]
    public async Task CollectAsync_CanExecuteIsFalse_ReturnsFailure_WithAttempt() {
        //Arrange
        var strategy = new FakeCollectionStrategy(false, "well now I am not doing it");
        
        // Act
        var result = await _strategyExecutor.CollectAsync("target machine", [], [strategy]);
        
        // Assert
        Assert.False(result.WasSuccessful);
        Assert.Null(result.Results);
        Assert.Null(result.SuccessfulStrategy);
        
        var attempt = result.FailureAttempts?.Single();
        Assert.Equal("well now I am not doing it", attempt?.FailureReason);
        Assert.Equal(strategy.GetType(), attempt?.StrategyType);
    }
    
    [Theory]
    [MemberData(nameof(StrategyExceptions))]
    public async Task CollectAsync_ThrowsException_ReturnsFailure_WithExceptionMessage(Exception strategyException) {
        //Arrange
        var strategy = new FakeCollectionStrategy(
            canExecute: true,
            exception: strategyException
        );
        
        // Act
        var result = await _strategyExecutor.CollectAsync("target machine", [], [strategy]);
        
        // Assert
        Assert.False(result.WasSuccessful);
        Assert.Null(result.Results);
        Assert.Null(result.SuccessfulStrategy);
        
        var attempt = result.FailureAttempts?.Single();
        Assert.Contains($"Collector failed: {strategyException.Message}.", attempt!.FailureReason!); 
        
        if (strategyException.InnerException is not null) 
            Assert.Contains($"\nInner Exception: {strategyException.InnerException}", attempt!.FailureReason!); 
        else 
            Assert.DoesNotContain("Inner Exception:", attempt!.FailureReason!);
    }
    
    public static IEnumerable<object[]> StrategyExceptions =>
    [
        [new Exception("Outer Exception")],
        [new Exception("Outer Exception", new Exception("Inner Exception"))]
    ];
    
    [Fact]
    public async Task CollectAsync_FirstStrategySuccessful_ReturnsSuccess_WithNoAttempts() {
        //Arrange
        var strategyResult = new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", 1, null, true);
        var strategy = new FakeCollectionStrategy(
            true,
            results: [strategyResult]
        );
        
        // Act
        var result = await _strategyExecutor.CollectAsync("target machine", [], [strategy]);
        
        // Assert
        Assert.True(result.WasSuccessful);
        Assert.Empty(result.FailureAttempts!);
        Assert.Equal(strategy.GetType(), result.SuccessfulStrategy);
        Assert.Equal(strategyResult, result.Results?.Single());
    }
    
    [Fact]
    public async Task CollectAsync_SecondStrategySuccessful_ReturnsSuccess_WithAttempt() {
        //Arrange
        var failedStrategy = new FakeCollectionStrategy(false, "well now I am not doing it");
        var strategyResult = new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", 1, null, true);
        var successfulStrategy = new FakeCollectionStrategy(
            true,
            results: [strategyResult]
        );
        
        // Act
        var result = await _strategyExecutor.CollectAsync("target machine", [], [failedStrategy, successfulStrategy]);
        
        // Assert
        Assert.True(result.WasSuccessful);
        Assert.Single(result.FailureAttempts!);
        Assert.Equal(successfulStrategy.GetType(), result.SuccessfulStrategy);
        Assert.Equal(strategyResult, result.Results?.Single());
    }
}

internal sealed class FakeCollectionStrategy(
    bool canExecute,
    string failureReason = "",
    Exception? exception = null,
    IEnumerable<RegistryQueryResult>? results = null
) : ICollectionStrategy<RegistryQueryResult, RegistryQuery> 
{
    public Task<(bool, string)> CanExecute(string target)
        => Task.FromResult((canExecute, failureReason));

    public Task<IEnumerable<RegistryQueryResult>> ExecuteAsync(
        string target,
        IEnumerable<RegistryQuery> queries) {
        if (exception is not null)
            throw exception;

        return Task.FromResult(results ?? []);
    }
}
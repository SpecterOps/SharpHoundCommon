using Xunit;

namespace CommonLibTest.CollectionDefinitons;

/// <summary>
/// Test that use cache cannot run in parallel, they can have flaky behavior
/// </summary>
[CollectionDefinition(nameof(CacheTestCollectionDefinition), DisableParallelization = true)]
public class CacheTestCollectionDefinition{}

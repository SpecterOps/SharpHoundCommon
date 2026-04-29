using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.Static;
using SharpHoundRPC.NetAPINative;
using SharpHoundRPC.PortScanner;

namespace SharpHoundCommonLib {
    internal class LdapConnectionPool : IDisposable {
        private readonly ConcurrentBag<LdapConnectionWrapper> _connections;
        private readonly ConcurrentBag<LdapConnectionWrapper> _globalCatalogConnection;
        private readonly string _identifier;
        private readonly string _poolIdentifier;
        private readonly LdapConfig _ldapConfig;
        private readonly ILogger _log;
        private readonly IPortScanner _portScanner;
        private readonly NativeMethods _nativeMethods;
        private readonly AdaptiveTimeout _queryAdaptiveTimeout;
        private readonly AdaptiveTimeout _pagedQueryAdaptiveTimeout;
        private readonly AdaptiveTimeout _rangedRetrievalAdaptiveTimeout;
        private readonly AdaptiveTimeout _testConnectionAdaptiveTimeout;
        private static readonly TimeSpan MinBackoffDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxBackoffDelay = TimeSpan.FromSeconds(20);
        private const int BackoffDelayMultiplier = 2;
        private const int MaxRetries = 3;
        private static readonly ConcurrentDictionary<string, NetAPIStructs.DomainControllerInfo?> DCInfoCache = new(StringComparer.OrdinalIgnoreCase);
        
        // Metrics
        private readonly IMetricRouter _metric;

        // Tracks domains we know we've determined we shouldn't try to connect to.
        private static readonly ConcurrentHashSet ExcludedDomains = new(StringComparer.OrdinalIgnoreCase);

        // Drops every exclusion record. Called from LdapUtils.ResetUtils so a fresh enumeration
        // pass after a configuration change isn't shadowed by stale exclusion state.
        internal static void ResetCaches() {
            DCInfoCache.Clear();
            ExcludedDomains.Clear();
        }

        public LdapConnectionPool(string identifier, string poolIdentifier, LdapConfig config,
            IPortScanner scanner = null, NativeMethods nativeMethods = null, ILogger log = null, IMetricRouter metric = null) {
            _connections = [];
            _globalCatalogConnection = [];
            _identifier = identifier;
            _poolIdentifier = poolIdentifier;
            _ldapConfig = config;
            _log = log ?? Logging.LogProvider.CreateLogger("LdapConnectionPool");
            _metric = metric ?? Metrics.Factory.CreateMetricRouter();
            _portScanner = scanner ?? new PortScanner();
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _queryAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger("LdapQuery"), useAdaptiveTimeout: false);
            _pagedQueryAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger("LdapPagedQuery"), useAdaptiveTimeout: false);
            _rangedRetrievalAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger("LdapRangedRetrieval"), useAdaptiveTimeout: false);
            _testConnectionAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger("TestLdapConnection"));
        }

        private async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)> GetLdapConnection(
            bool globalCatalog) {
            if (globalCatalog) {
                return await GetGlobalCatalogConnectionAsync();
            }

            return await GetConnectionAsync();
        }
        
        private void LatencyObservation(double latency) => _metric.Observe(LdapMetricDefinitions.RequestLatency, latency,
            new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));

        public async IAsyncEnumerable<LdapResult<IDirectoryObject>> Query(LdapQueryParameters queryParameters,
            [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
            var setupResult = await SetupLdapQuery(queryParameters);

            if (!setupResult.Success) {
                _log.LogInformation("Query - Failure during query setup: {Reason}\n{Info}", setupResult.Message,
                    queryParameters.GetQueryInfo());
                yield break;
            }

            var searchRequest = setupResult.SearchRequest;
            var connectionWrapper = setupResult.ConnectionWrapper;

            if (cancellationToken.IsCancellationRequested) {
                ReleaseConnection(connectionWrapper);
                yield break;
            }

            var queryRetryCount = 0;
            var busyRetryCount = 0;
            LdapResult<IDirectoryObject> errorResult = null;
            var querySuccess = false;
            SearchResponse response = null;

            /*
             * Retry loop structure:
             *   queryRetryCount — tracks connection-level failures (null response, ServerDown). On ServerDown,
             *     an inner retry loop attempts to establish a new connection before the outer loop continues.
             *   busyRetryCount — tracks server-busy/timeout conditions. The same connection is reused after
             *     an exponential backoff delay, since the server is expected to become available again.
             */
            while (!cancellationToken.IsCancellationRequested) {
                try {
                    _log.LogTrace("Sending ldap request - {Info}", queryParameters.GetQueryInfo());
                    response = await SendRequestWithTimeout(connectionWrapper.Connection, searchRequest, _queryAdaptiveTimeout);

                    if (response != null) {
                        querySuccess = true;
                    } else if (queryRetryCount == MaxRetries) {
                        _metric.Observe(LdapMetricDefinitions.FailedRequests, 1, 
                            new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                        errorResult =
                            LdapResult<IDirectoryObject>.Fail($"Failed to get a response after {MaxRetries} attempts",
                                queryParameters);
                    }
                    else {
                        _metric.Observe(LdapMetricDefinitions.FailedRequests, 1, 
                            new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                        queryRetryCount++;
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown &&
                                                 queryRetryCount < MaxRetries) {
                    /*
                     * A ServerDown exception indicates that our connection is no longer valid for one of many reasons.
                     * We'll want to release our connection back to the pool, but dispose it. We need a new connection,
                     * and because this is not a paged query, we can get this connection from anywhere.
                     *
                     * We use queryRetryCount here to prevent an infinite retry loop from occurring
                     *
                     * Release our connection in a faulted state since the connection is defunct. Attempt to get a new connection to any server in the domain
                     * since non-paged queries do not require same server connections
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1, 
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    queryRetryCount++;
                    _log.LogDebug("Query - Attempting to recover from ServerDown for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), queryRetryCount);
                    //Call ReleaseConnection with faulted = true
                    ReleaseConnection(connectionWrapper, true);

                    //Try MaxRetries times to get a new connection
                    for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                        var backoffDelay = GetNextBackoff(retryCount);
                        await Task.Delay(backoffDelay, cancellationToken);
                        var (success, newConnectionWrapper, _) =
                            await GetLdapConnection(queryParameters.GlobalCatalog);
                        if (success) {
                            _log.LogDebug(
                                "Query - Recovered from ServerDown successfully, connection made to {NewServer}",
                                newConnectionWrapper.GetServer());
                            connectionWrapper = newConnectionWrapper;
                            break;
                        }

                        //If we hit our max retries for making a new connection, set errorResult so we can yield it after this logic
                        if (retryCount == MaxRetries - 1) {
                            _log.LogError("Query - Failed to get a new connection after ServerDown.\n{Info}",
                                queryParameters.GetQueryInfo());
                            errorResult =
                                LdapResult<IDirectoryObject>.Fail(
                                    "Query - Failed to get a new connection after ServerDown.", queryParameters,
                                    le.ErrorCode);
                        }
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                    /*
                     * If we get a busy error, we want to do an exponential backoff, but maintain the current connection
                     * The expectation is that given enough time, the server should stop being busy and service our query appropriately
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1, 
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    busyRetryCount++;
                    _log.LogDebug("Query - Executing busy backoff for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), busyRetryCount);
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                }
                catch (TimeoutException) when (busyRetryCount < MaxRetries) {
                    /*
                     * Treat a timeout as a busy error
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1, 
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    busyRetryCount++;
                    _log.LogDebug("Query - Timeout: Executing busy backoff for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), busyRetryCount);
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                }
                catch (LdapException le) {
                    /*
                     * This is our fallback catch. If our retry counts have been exhausted this will trigger and break us out of our loop
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    errorResult = LdapResult<IDirectoryObject>.Fail(
                        $"Query - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                        queryParameters, le.ErrorCode);
                }
                catch (Exception e) {
                    /*
                     * Generic exception handling for unforeseen circumstances
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    errorResult =
                        LdapResult<IDirectoryObject>.Fail($"Query - Caught unrecoverable exception: {e.Message}",
                            queryParameters);
                }

                //If we have a errorResult set it means we hit an error we couldn't recover from, so yield that result and then break out of the function
                if (errorResult != null) {
                    if (errorResult.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                        ReleaseConnection(connectionWrapper, true);
                    }
                    else {
                        ReleaseConnection(connectionWrapper);
                    }

                    yield return errorResult;
                    yield break;
                }

                //If we've successfully made our query, break out of the while loop
                if (querySuccess) {
                    break;
                }
            }

            ReleaseConnection(connectionWrapper);
            foreach (SearchResultEntry entry in response.Entries) {
                yield return LdapResult<IDirectoryObject>.Ok(new SearchResultEntryWrapper(entry));
            }
        }

        public async IAsyncEnumerable<LdapResult<IDirectoryObject>> PagedQuery(LdapQueryParameters queryParameters,
            [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
            var setupResult = await SetupLdapQuery(queryParameters);

            if (!setupResult.Success) {
                _log.LogInformation("PagedQuery - Failure during query setup: {Reason}\n{Info}", setupResult.Message,
                    queryParameters.GetQueryInfo());
                yield break;
            }

            var searchRequest = setupResult.SearchRequest;
            var connectionWrapper = setupResult.ConnectionWrapper;
            var serverName = setupResult.Server;

            if (serverName == null) {
                _log.LogWarning("PagedQuery - Failed to get a server name for connection, retry not possible");
            }

            var pageControl = new PageResultRequestControl(500);
            searchRequest.Controls.Add(pageControl);

            PageResultResponseControl pageResponse = null;
            var busyRetryCount = 0;
            var queryRetryCount = 0;
            
            LdapResult<IDirectoryObject> errorResult = null;

            /*
             * Retry loop structure:
             *   queryRetryCount — tracks connection-level failures (null response, ServerDown). On ServerDown,
             *     an inner retry loop attempts to establish a new connection to the same server before the
             *     outer loop continues. Same-server reconnection is required because the LDAP server holds
             *     paging state (the cookie) per-connection; switching servers would invalidate that state.
             *   busyRetryCount — tracks server-busy/timeout conditions. The same connection is reused after
             *     an exponential backoff delay, since the server is expected to become available again.
             *     This counter resets to 0 after each successful page to give every page a fresh budget.
             */
            while (!cancellationToken.IsCancellationRequested) {
                SearchResponse response = null;
                try {
                    _log.LogTrace("Sending paged ldap request - {Info}", queryParameters.GetQueryInfo());
                    response = await SendRequestWithTimeout(connectionWrapper.Connection, searchRequest, _pagedQueryAdaptiveTimeout);
                    if (response != null) {
                        pageResponse = (PageResultResponseControl)response.Controls
                            .Where(x => x is PageResultResponseControl).DefaultIfEmpty(null).FirstOrDefault();
                    } else if (queryRetryCount == MaxRetries) {
                        _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                            new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                        errorResult = LdapResult<IDirectoryObject>.Fail(
                            $"PagedQuery - Failed to get a response after {MaxRetries} attempts",
                            queryParameters);
                    }
                    else {
                        _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                            new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                        queryRetryCount++;
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown && queryRetryCount < MaxRetries) {
                    /*
                     * A ServerDown exception indicates that our connection is no longer valid for one of many reasons.
                     * We'll want to release our connection back to the pool, but dispose it. We need a new connection.
                     *
                     * Unlike non-paged queries, paged queries MUST reconnect to the same server because the server
                     * maintains paging state (the cookie) per-connection. Connecting to a different server would
                     * invalidate the cookie and the query would have to restart from scratch.
                     *
                     * We use queryRetryCount here to prevent an infinite retry loop from occurring.
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    if (serverName == null) {
                        // Because we MUST connect back to the original server, if we don't have the server to connect too, we just have to exit out here
                        _log.LogError(
                            "PagedQuery - Received server down exception without a known servername. Unable to generate new connection\n{Info}",
                            queryParameters.GetQueryInfo());
                        ReleaseConnection(connectionWrapper, true);
                        yield break;
                    }

                    queryRetryCount++;
                    _log.LogDebug(
                        "PagedQuery - Attempting to recover from ServerDown for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), queryRetryCount);

                    ReleaseConnection(connectionWrapper, true);
                    for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                        var backoffDelay = GetNextBackoff(retryCount);
                        await Task.Delay(backoffDelay, cancellationToken);
                        var (success, ldapConnectionWrapperNew, _) =
                            await GetConnectionForSpecificServerActuallyAsync(serverName, queryParameters.GlobalCatalog);

                        if (success) {
                            _log.LogDebug("PagedQuery - Recovered from ServerDown successfully");
                            connectionWrapper = ldapConnectionWrapperNew;
                            break;
                        }

                        if (retryCount == MaxRetries - 1) {
                            _log.LogError("PagedQuery - Failed to get a new connection after ServerDown.\n{Info}",
                                queryParameters.GetQueryInfo());
                            errorResult =
                                LdapResult<IDirectoryObject>.Fail(
                                    "PagedQuery - Failed to get a new connection after ServerDown.",
                                    queryParameters, le.ErrorCode);
                        }
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                    /*
                     * If we get a busy error, we want to do an exponential backoff, but maintain the current connection
                     * The expectation is that given enough time, the server should stop being busy and service our query appropriately
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1, 
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    busyRetryCount++;
                    _log.LogDebug("PagedQuery - Executing busy backoff for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), busyRetryCount);
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                }
                catch (TimeoutException) when (busyRetryCount < MaxRetries) {
                    /*
                     * Treat a timeout as a busy error
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    busyRetryCount++;
                    _log.LogDebug("PagedQuery - Timeout: Executing busy backoff for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), busyRetryCount);
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                }
                catch (LdapException le) {
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    errorResult = LdapResult<IDirectoryObject>.Fail(
                        $"PagedQuery - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                        queryParameters, le.ErrorCode);
                }
                catch (Exception e) {
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    errorResult =
                        LdapResult<IDirectoryObject>.Fail($"PagedQuery - Caught unrecoverable exception: {e.Message}",
                            queryParameters);
                }

                if (errorResult != null) {
                    if (errorResult.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                        ReleaseConnection(connectionWrapper, true);
                    }
                    else {
                        ReleaseConnection(connectionWrapper);
                    }

                    yield return errorResult;
                    yield break;
                }

                if (cancellationToken.IsCancellationRequested) {
                    ReleaseConnection(connectionWrapper);
                    yield break;
                }

                //I'm not sure why this happens sometimes, but if we try the request again, it works sometimes, other times we get an exception
                if (response == null || pageResponse == null) {
                    continue;
                }

                // Reset busy and query retry count after a successfully delivered page so each page starts with a fresh budget
                busyRetryCount = 0;
                queryRetryCount = 0;

                foreach (SearchResultEntry entry in response.Entries) {
                    if (cancellationToken.IsCancellationRequested) {
                        ReleaseConnection(connectionWrapper);
                        yield break;
                    }

                    yield return LdapResult<IDirectoryObject>.Ok(new SearchResultEntryWrapper(entry));
                }

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0 ||
                    cancellationToken.IsCancellationRequested) {
                    ReleaseConnection(connectionWrapper);
                    yield break;
                }

                pageControl.Cookie = pageResponse.Cookie;
            }
        }

        private async Task<LdapQuerySetupResult> SetupLdapQuery(LdapQueryParameters queryParameters) {
            var result = new LdapQuerySetupResult();
            var (success, connectionWrapper, message) =
                await GetLdapConnection(queryParameters.GlobalCatalog);
            if (!success) {
                result.Success = false;
                result.Message = $"Unable to create a connection: {message}";
                return result;
            }

            //This should never happen as far as I know, so just checking for safety
            if (connectionWrapper.Connection == null) {
                result.Success = false;
                result.Message = "Connection object is null";
                return result;
            }

            var (searchRequestSuccess, searchRequest) = await CreateSearchRequestAsync(queryParameters, connectionWrapper);
            if (!searchRequestSuccess) {
                result.Success = false;
                result.Message = "Failed to create search request";
                ReleaseConnection(connectionWrapper);
                return result;
            }

            result.Server = connectionWrapper.GetServer();
            result.Success = true;
            result.SearchRequest = searchRequest;
            result.ConnectionWrapper = connectionWrapper;
            return result;
        }

        public async IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
            string attributeName, [EnumeratorCancellation] CancellationToken cancellationToken = new()) {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            var connectionResult = await GetConnectionAsync();
            if (!connectionResult.Success) {
                yield return Result<string>.Fail(connectionResult.Message);
                yield break;
            }

            var index = 0;
            var step = 0;

            //Start by using * as our upper index, which will automatically give us the range size
            var currentRange = $"{attributeName};range={index}-*";
            var complete = false;

            var queryParameters = new LdapQueryParameters {
                DomainName = domain,
                LDAPFilter = $"{attributeName}=*",
                Attributes = new[] { currentRange },
                SearchScope = SearchScope.Base,
                SearchBase = distinguishedName
            };
            var connectionWrapper = connectionResult.ConnectionWrapper;

            var (searchRequestSuccess, searchRequest) = await CreateSearchRequestAsync(queryParameters, connectionWrapper);
            if (!searchRequestSuccess) {
                ReleaseConnection(connectionWrapper);
                yield return Result<string>.Fail("Failed to create search request");
                yield break;
            }

            var queryRetryCount = 0;
            var busyRetryCount = 0;

            LdapResult<string> errorResult = null;

            /*
             * Retry loop structure:
             *   queryRetryCount — tracks connection-level failures (null response, ServerDown). On ServerDown,
             *     an inner retry loop attempts to establish a new connection before the outer loop continues.
             *     This counter resets to 0 after each successful range chunk to give subsequent chunks a fresh budget.
             *   busyRetryCount — tracks server-busy/timeout conditions. The same connection is reused after
             *     an exponential backoff delay, since the server is expected to become available again.
             *     This counter resets to 0 after each successful range chunk to give subsequent chunks a fresh budget.
             */
            while (!cancellationToken.IsCancellationRequested) {
                SearchResponse response = null;

                try {
                    response = await SendRequestWithTimeout(connectionWrapper.Connection, searchRequest, _rangedRetrievalAdaptiveTimeout);
                    if (response != null) {
                        // Reset retry counters on a successful response so the next range chunk starts with a fresh budget
                        queryRetryCount = 0;
                        busyRetryCount = 0;
                    }
                    else if (queryRetryCount == MaxRetries) {
                        errorResult = LdapResult<string>.Fail(
                            $"RangedRetrieval - Failed to get a response after {MaxRetries} attempts",
                            queryParameters);
                    }
                    else {
                        _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                            new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                        queryRetryCount++;
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown &&
                                                 queryRetryCount < MaxRetries) {
                    /*
                     * A ServerDown exception indicates that our connection is no longer valid for one of many reasons.
                     * We'll want to release our connection back to the pool, but dispose it. We need a new connection,
                     * and because ranged retrieval does not use paging state, we can connect to any server in the domain.
                     *
                     * We use queryRetryCount here to prevent an infinite retry loop from occurring.
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    queryRetryCount++;
                    _log.LogDebug(
                        "RangedRetrieval - Attempting to recover from ServerDown for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), queryRetryCount);
                    //Call ReleaseConnection with faulted = true
                    ReleaseConnection(connectionWrapper, true);
                    
                    for (var retryCount = 0; retryCount < MaxRetries; retryCount++) {
                        var backoffDelay = GetNextBackoff(retryCount);
                        await Task.Delay(backoffDelay, cancellationToken);
                        var (success, newConnectionWrapper, message) =
                            await GetLdapConnection(false);
                        if (success) {
                            _log.LogDebug(
                                "RangedRetrieval - Recovered from ServerDown successfully, connection made to {NewServer}",
                                newConnectionWrapper.GetServer());
                            connectionWrapper = newConnectionWrapper;
                            break;
                        }

                        //If we hit our max retries for making a new connection, set tempResult so we can yield it after this logic
                        if (retryCount == MaxRetries - 1) {
                            _log.LogError(
                                "RangedRetrieval - Failed to get a new connection after ServerDown for path {Path}",
                                distinguishedName);
                            errorResult =
                                LdapResult<string>.Fail(
                                    "RangedRetrieval - Failed to get a new connection after ServerDown.",
                                    queryParameters, le.ErrorCode);
                        }
                    }
                }
                catch (LdapException le) when (le.ErrorCode == (int)ResultCode.Busy && busyRetryCount < MaxRetries) {
                    /*
                     * If we get a busy error, we want to do an exponential backoff, but maintain the current connection.
                     * The expectation is that given enough time, the server should stop being busy and service our query appropriately.
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    busyRetryCount++;
                    _log.LogDebug("RangedRetrieval - Executing busy backoff for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), busyRetryCount);
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                }
                catch (TimeoutException) when (busyRetryCount < MaxRetries) {
                    /*
                     * Treat a timeout as a busy error
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    busyRetryCount++;
                    _log.LogDebug("RangedRetrieval - Timeout: Executing busy backoff for query {Info} (Attempt {Count})",
                        queryParameters.GetQueryInfo(), busyRetryCount);
                    var backoffDelay = GetNextBackoff(busyRetryCount);
                    await Task.Delay(backoffDelay, cancellationToken);
                }
                catch (LdapException le) {
                    /*
                     * This is our fallback catch. If our retry counts have been exhausted this will trigger and break us out of our loop
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    errorResult = LdapResult<string>.Fail(
                        $"RangedRetrieval - Caught unrecoverable ldap exception: {le.Message} (ServerMessage: {le.ServerErrorMessage}) (ErrorCode: {le.ErrorCode})",
                        queryParameters, le.ErrorCode);
                }
                catch (Exception e) {
                    /*
                     * Generic exception handling for unforeseen circumstances
                     */
                    _metric.Observe(LdapMetricDefinitions.FailedRequests, 1,
                        new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
                    errorResult =
                        LdapResult<string>.Fail($"RangedRetrieval - Caught unrecoverable exception: {e.Message}", queryParameters);
                }

                //If we have a errorResult set it means we hit an error we couldn't recover from, so yield that result and then break out of the function
                //We handle connection release in the relevant exception blocks
                if (errorResult != null) {
                    if (errorResult.ErrorCode == (int)LdapErrorCodes.ServerDown) {
                        ReleaseConnection(connectionWrapper, true);
                    }
                    else {
                        ReleaseConnection(connectionWrapper);
                    }

                    yield return errorResult;
                    yield break;
                }
                
                if (response == null) {
                    // response is null when queryRetryCount has been incremented but MaxRetries not yet reached;
                    // the outer while loop will retry automatically
                    continue;
                }

                if (response.Entries.Count == 1) {
                    var entry = response.Entries[0];
                    //We dont know the name of our attribute, but there should only be one, so we're safe to just use a loop here
                    foreach (string attr in entry.Attributes.AttributeNames) {
                        currentRange = attr;
                        complete = currentRange.IndexOf("*", 0, StringComparison.OrdinalIgnoreCase) > 0;
                        step = entry.Attributes[currentRange].Count;
                    }

                    //Release our connection before we iterate
                    if (complete) {
                        ReleaseConnection(connectionWrapper);
                    }

                    foreach (string dn in entry.Attributes[currentRange].GetValues(typeof(string))) {
                        yield return Result<string>.Ok(dn);
                        index++;
                    }

                    if (complete) {
                        yield break;
                    }

                    currentRange = $"{attributeName};range={index}-{index + step}";
                    searchRequest.Attributes.Clear();
                    searchRequest.Attributes.Add(currentRange);
                }
                else {
                    //I dont know what can cause a RR to have multiple entries, but its nothing good. Break out
                    ReleaseConnection(connectionWrapper);
                    yield break;
                }
            }

            ReleaseConnection(connectionWrapper);
        }

        private static TimeSpan GetNextBackoff(int retryCount) {
            return TimeSpan.FromSeconds(Math.Min(
                MinBackoffDelay.TotalSeconds * Math.Pow(BackoffDelayMultiplier, retryCount),
                MaxBackoffDelay.TotalSeconds));
        }

        private async Task<(bool, SearchRequest)> CreateSearchRequestAsync(LdapQueryParameters queryParameters,
            LdapConnectionWrapper connectionWrapper) {
            string basePath;
            if (!string.IsNullOrWhiteSpace(queryParameters.SearchBase)) {
                basePath = queryParameters.SearchBase;
            } else if (!connectionWrapper.GetSearchBase(queryParameters.NamingContext, out basePath)) {
                string tempPath;
                if (CallDsGetDcName(queryParameters.DomainName, out var info) && info != null) {
                    tempPath = Helpers.DomainNameToDistinguishedName(info.Value.DomainName);
                    connectionWrapper.SaveContext(queryParameters.NamingContext, tempPath);
                }
                else {
                    // Controlled replacement for LdapUtils.GetDomain + DomainNameToDistinguishedName.
                    // Pass null for the pool: this code runs *inside* an LdapConnectionPool, so
                    // attempting controlled resolution via the pool would reenter us. The static
                    // helper will fall through to the uncontrolled fallback, which itself honors
                    // LdapConfig.AllowFallbackToUncontrolledLdap.
                    var (ok, domainInfo) = await LdapUtils
                        .GetDomainInfoStaticAsync(queryParameters.DomainName, _ldapConfig, _log);
                    if (!ok || string.IsNullOrWhiteSpace(domainInfo?.DistinguishedName)) {
                        return (false, null);
                    }

                    tempPath = domainInfo.DistinguishedName;
                }

                basePath = queryParameters.NamingContext switch {
                    NamingContext.Configuration => $"CN=Configuration,{tempPath}",
                    NamingContext.Schema => $"CN=Schema,CN=Configuration,{tempPath}",
                    NamingContext.Default => tempPath,
                    _ => throw new ArgumentOutOfRangeException()
                };

                connectionWrapper.SaveContext(queryParameters.NamingContext, basePath);
            }

            if (string.IsNullOrWhiteSpace(queryParameters.SearchBase) &&
                !string.IsNullOrWhiteSpace(queryParameters.RelativeSearchBase)) {
                basePath = $"{queryParameters.RelativeSearchBase},{basePath}";
            }

            var searchRequest = new SearchRequest(basePath, queryParameters.LDAPFilter, queryParameters.SearchScope,
                queryParameters.Attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            if (queryParameters.IncludeDeleted) {
                searchRequest.Controls.Add(new ShowDeletedControl());
            }

            if (queryParameters.IncludeSecurityDescriptor) {
                searchRequest.Controls.Add(new SecurityDescriptorFlagControl {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });
            }

            return (true, searchRequest);
        }

        private bool CallDsGetDcName(string domainName, out NetAPIStructs.DomainControllerInfo? info) {
            if (DCInfoCache.TryGetValue(domainName.ToUpper().Trim(), out info)) return info != null;

            // Blocking External Call
            var apiResult = _nativeMethods.CallDsGetDcName(null, domainName,
                (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                       NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));

            if (apiResult.IsFailed) {
                DCInfoCache.TryAdd(domainName.ToUpper().Trim(), null);
                return false;
            }

            info = apiResult.Value;
            return true;
        }

        public async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)>
            GetConnectionAsync() {
            if (ExcludedDomains.Contains(_identifier)) {
                return (false, null, $"Identifier {_identifier} excluded for connection attempt");
            }

            if (!_connections.TryTake(out var connectionWrapper)) {
                var (success, connection, message) = await CreateNewConnection();
                if (!success) {
                    return (false, null, message);
                }

                connectionWrapper = connection;
            }

            return (true, connectionWrapper, null);
        }

        /// <summary>
        /// It's not async.  Use GetConnectionForSpecificServerActuallyAsync if looking for a Task.
        /// </summary>
        /// <param name="server"></param>
        /// <param name="globalCatalog"></param>
        /// <returns></returns>
        public (bool Success, LdapConnectionWrapper connectionWrapper, string Message)
            GetConnectionForSpecificServerAsync(string server, bool globalCatalog) {
            return CreateNewConnectionForServer(server, globalCatalog).GetAwaiter().GetResult();
        }

        public async Task<(bool Success, LdapConnectionWrapper connectionWrapper, string Message)>
            GetConnectionForSpecificServerActuallyAsync(string server, bool globalCatalog) {
            return await CreateNewConnectionForServer(server, globalCatalog);
        }

        public async Task<(bool Success, LdapConnectionWrapper ConnectionWrapper, string Message)>
            GetGlobalCatalogConnectionAsync() {
            if (ExcludedDomains.Contains(_identifier)) {
                return (false, null, $"Identifier {_identifier} excluded for connection attempt");
            }

            if (!_globalCatalogConnection.TryTake(out var connectionWrapper)) {
                var (success, connection, message) = await CreateNewConnection(true);
                if (!success) {
                    return (false, null, message);
                }

                connectionWrapper = connection;
            }

            return (true, connectionWrapper, null);
        }

        public void ReleaseConnection(LdapConnectionWrapper connectionWrapper, bool connectionFaulted = false) {
            if (!connectionFaulted) {
                if (connectionWrapper.GlobalCatalog) {
                    _globalCatalogConnection.Add(connectionWrapper);
                }
                else {
                    _connections.Add(connectionWrapper);
                }
            }
            else {
                connectionWrapper.Connection?.Dispose();
            }
        }

        public void Dispose() {
            while (_connections.TryTake(out var wrapper)) {
                wrapper.Connection?.Dispose();
            }
            
            while (_globalCatalogConnection.TryTake(out var wrapper)) {
                wrapper.Connection?.Dispose();
            }
        }

        private async Task<(bool Success, LdapConnectionWrapper Connection, string Message)> CreateNewConnection(
            bool globalCatalog = false) {
            try {
                if (!string.IsNullOrWhiteSpace(_ldapConfig.Server)) {
                    return await CreateNewConnectionForServer(_ldapConfig.Server, globalCatalog);
                }

                if (await CreateLdapConnection(_identifier.ToUpper().Trim(), globalCatalog) is (true, var connectionWrapper1)) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 1. SSL: {SSl}",
                        _identifier, connectionWrapper1.Connection.SessionOptions.SecureSocketLayer);
                    return (true, connectionWrapper1, "");
                }

                string tempDomainName;

                // Blocking External Call
                var dsGetDcNameResult = _nativeMethods.CallDsGetDcName(null, _identifier,
                    (uint)(NetAPIEnums.DSGETDCNAME_FLAGS.DS_FORCE_REDISCOVERY |
                           NetAPIEnums.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                           NetAPIEnums.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED));
                if (dsGetDcNameResult.IsSuccess) {
                    tempDomainName = dsGetDcNameResult.Value.DomainName;

                    if (!tempDomainName.Equals(_identifier, StringComparison.OrdinalIgnoreCase) &&
                        await CreateLdapConnection(tempDomainName, globalCatalog) is (true, var connectionWrapper2)) {
                        _log.LogDebug(
                            "Successfully created ldap connection for domain: {Domain} using strategy 2 with name {NewName}",
                            _identifier, tempDomainName);
                        return (true, connectionWrapper2, "");
                    }

                    var server = dsGetDcNameResult.Value.DomainControllerName.TrimStart('\\');

                    var result =
                        await CreateLDAPConnectionWithPortCheck(server, globalCatalog);
                    if (result.success) {
                        _log.LogDebug(
                            "Successfully created ldap connection for domain: {Domain} using strategy 3 to server {Server}",
                            _identifier, server);
                        return (true, result.connection, "");
                    }
                }

                // Controlled replacement for LdapUtils.GetDomain. The static helper still honors
                // LdapConfig.AllowFallbackToUncontrolledLdap for the uncontrolled fallback.
                var (infoOk, info) =
                    await LdapUtils.GetDomainInfoStaticAsync(_identifier, _ldapConfig, _log);
                if (!infoOk || string.IsNullOrEmpty(info?.Name)) {
                    //If we don't get a result here, we effectively have no other ways to resolve this domain, so we'll just have to exit out
                    _log.LogDebug(
                        "Could not resolve domain info, unable to create ldap connection for domain {Domain}",
                        _identifier);
                    ExcludedDomains.Add(_identifier);
                    return (false, null, "Unable to get domain info for further strategies");
                }

                tempDomainName = info.Name.ToUpper().Trim();

                if (!tempDomainName.Equals(_identifier, StringComparison.OrdinalIgnoreCase) &&
                    await CreateLdapConnection(tempDomainName, globalCatalog) is (true, var connectionWrapper4)) {
                    _log.LogDebug(
                        "Successfully created ldap connection for domain: {Domain} using strategy 4 with name {NewName}",
                        _identifier, tempDomainName);
                    return (true, connectionWrapper4, "");
                }

                if (!string.IsNullOrEmpty(info.PrimaryDomainController)) {
                    var primaryDomainController = info.PrimaryDomainController;
                    var portConnectionResult =
                        await CreateLDAPConnectionWithPortCheck(primaryDomainController, globalCatalog);
                    if (portConnectionResult.success) {
                        _log.LogDebug(
                            "Successfully created ldap connection for domain: {Domain} using strategy 5 with to pdc {Server}",
                            _identifier, primaryDomainController);
                        return (true, portConnectionResult.connection, "");
                    }
                }

                foreach (var dcName in info.DomainControllers) {
                    if (string.IsNullOrEmpty(dcName)) continue;
                    var portConnectionResult =
                        await CreateLDAPConnectionWithPortCheck(dcName, globalCatalog);
                    if (portConnectionResult.success) {
                        _log.LogDebug(
                            "Successfully created ldap connection for domain: {Domain} using strategy 6 to dc {Server}",
                            _identifier, dcName);
                        return (true, portConnectionResult.connection, "");
                    }
                }
            }
            catch (Exception e) {
                _log.LogInformation(e, "We will not be able to connect to domain {Domain} by any strategy, leaving it.",
                    _identifier);
                ExcludedDomains.Add(_identifier);
            }

            return (false, null, "All attempted connections failed");
        }

        private async Task<(bool Success, LdapConnectionWrapper Connection, string Message)> CreateNewConnectionForServer(
            string identifier, bool globalCatalog = false) {
            if (await CreateLdapConnection(identifier, globalCatalog) is (true, var serverConnection)) {
                return (true, serverConnection, "");
            }

            return (false, null, $"Failed to create ldap connection for {identifier}");
        }

        private async Task<(bool, LdapConnectionWrapper)> CreateLdapConnection(string target, bool globalCatalog) {
            var baseConnection = CreateBaseConnection(target, true, globalCatalog);
            if (await TestLdapConnection(baseConnection) is (true, var result)) {
                var connection = new LdapConnectionWrapper(baseConnection, result.SearchResultEntry, globalCatalog,
                    _poolIdentifier);
                return (true, connection);
            }

            try {
                baseConnection.Dispose();
            }
            catch {
                //this is just in case
            }

            if (_ldapConfig.ForceSSL) {
                return (false, null);
            }

            baseConnection = CreateBaseConnection(target, false, globalCatalog);
            if (await TestLdapConnection(baseConnection) is (true, var resultNoSSL)) {
                var connection = new LdapConnectionWrapper(baseConnection, resultNoSSL.SearchResultEntry, globalCatalog,
                    _poolIdentifier);
                return (true, connection);
            }

            try {
                baseConnection.Dispose();
            }
            catch {
                //this is just in case
            }

            return (false, null);
        }

        private LdapConnection CreateBaseConnection(string directoryIdentifier, bool ssl,
            bool globalCatalog) {
            _log.LogDebug("Creating connection for identifier {Identifier}", directoryIdentifier);
            var port = globalCatalog ? _ldapConfig.GetGCPort(ssl) : _ldapConfig.GetPort(ssl);
            var identifier = new LdapDirectoryIdentifier(directoryIdentifier, port, false, false);
            var connection = new LdapConnection(identifier) { Timeout = new TimeSpan(0, 0, 5, 0) };

            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            //Referral chasing does not work with paged searches 
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (ssl) connection.SessionOptions.SecureSocketLayer = true;

            if (_ldapConfig.DisableSigning || ssl) {
                connection.SessionOptions.Signing = false;
                connection.SessionOptions.Sealing = false;
            }
            else {
                connection.SessionOptions.Signing = true;
                connection.SessionOptions.Sealing = true;
            }

            if (_ldapConfig.DisableCertVerification)
                connection.SessionOptions.VerifyServerCertificate = (_, _) => true;

            if (_ldapConfig.Username != null) {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
                connection.Credential = cred;
            }

            connection.AuthType = _ldapConfig.AuthType;

            return connection;
        }

        /// <summary>
        ///     Tests whether an LDAP connection is working
        /// </summary>
        /// <param name="connection">The ldap connection object to test</param>
        /// <param name="testResult">The results fo the connection test</param>
        /// <returns>True if connection was successful, false otherwise</returns>
        /// <exception cref="LdapAuthenticationException">Something is wrong with the supplied credentials</exception>
        /// <exception cref="NoLdapDataException">
        ///     A connection "succeeded" but no data was returned. This can be related to
        ///     kerberos auth across trusts or just simply lack of permissions
        /// </exception>
        private async Task<(bool, LdapConnectionTestResult)> TestLdapConnection(LdapConnection connection) {
            var testResult = new LdapConnectionTestResult();
            try {
                //Attempt an initial bind. If this fails, likely auth is invalid, or its not a valid target
                // Blocking External Call
                connection.Bind();
            }
            catch (LdapException e) {
                if (e.ErrorCode is (int)LdapErrorCodes.InvalidCredentials
                    or (int)ResultCode.InappropriateAuthentication) {
                    connection.Dispose();
                    throw new LdapAuthenticationException(e);
                }

                testResult.Message = e.Message;
                testResult.ErrorCode = e.ErrorCode;
                return (false, testResult);
            }
            catch (Exception e) {
                testResult.Message = e.Message;
                return (false, testResult);
            }

            SearchResponse response = null;
            try {
                //Do an initial search request to get the rootDSE
                //This ldap filter is equivalent to (objectclass=*)
                var searchRequest = CreateSearchRequest("", new LdapFilter().AddAllObjects().GetFilter(),
                    SearchScope.Base, null);

                await Helpers.RetryOnException<TimeoutException>(async () => {
                    response = await SendRequestWithTimeout(connection, searchRequest, _testConnectionAdaptiveTimeout);
                }, retryCount: 2, logger: _log);
            }
            catch (TimeoutException e) {
                /*
                 * We've retried this connection a few times but haven't succeeded
                 */
                testResult.Message = e.Message;
                return (false, testResult);
            }
            catch (LdapException e) {
                /*
                 * If we can't send the initial search request, its unlikely any other search requests will work so we will immediately return false
                 */
                testResult.Message = e.Message;
                testResult.ErrorCode = e.ErrorCode;
                return (false, testResult);
            }

            if (response?.Entries == null || response.Entries.Count == 0) {
                /*
                 * This can happen for one of two reasons, either we dont have permission to query AD or we're authenticating
                 * across external trusts with kerberos authentication without Forest Search Order properly configured.
                 * Either way, this connection isn't useful for us because we're not going to get data, so return false
                 */

                connection.Dispose();
                throw new NoLdapDataException();
            }

            testResult.SearchResultEntry = new SearchResultEntryWrapper(response.Entries[0]);
            testResult.Message = "";
            return (true, testResult);
        }

        private class LdapConnectionTestResult {
            public string Message { get; set; }
            public IDirectoryObject SearchResultEntry { get; set; }
            public int ErrorCode { get; set; }
        }

        private async Task<(bool success, LdapConnectionWrapper connection)> CreateLDAPConnectionWithPortCheck(
            string target, bool globalCatalog) {
            if (globalCatalog) {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(true)) || (!_ldapConfig.ForceSSL &&
                        await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(false))))
                    return await CreateLdapConnection(target, true);
            }
            else {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetPort(true)) || (!_ldapConfig.ForceSSL &&
                        await _portScanner.CheckPort(target, _ldapConfig.GetPort(false))))
                    return await CreateLdapConnection(target, false);
            }

            return (false, null);
        }

        private SearchRequest CreateSearchRequest(string distinguishedName, string ldapFilter,
            SearchScope searchScope,
            string[] attributes) {
            var searchRequest = new SearchRequest(distinguishedName, ldapFilter,
                searchScope, attributes);
            searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            return searchRequest;
        }

        private async Task<SearchResponse> SendRequestWithTimeout(LdapConnection connection, SearchRequest request, AdaptiveTimeout adaptiveTimeout) {
            // Prerequest metrics
            var concurrentRequests = LdapMetrics.IncrementInFlight();
            _metric.Observe(LdapMetricDefinitions.ConcurrentRequests, concurrentRequests, 
                new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
            
            // Add padding to account for network latency and processing overhead
            const int TimeoutPaddingSeconds = 3;
            var timeout = adaptiveTimeout.GetAdaptiveTimeout();
            var timeoutWithPadding = timeout + TimeSpan.FromSeconds(TimeoutPaddingSeconds);
            var result = await adaptiveTimeout.ExecuteWithTimeout((_) => connection.SendRequestAsync(request, timeoutWithPadding), latencyObservation: LatencyObservation);
            
            // Postrequest metrics
            concurrentRequests = LdapMetrics.DecrementInFlight();
            _metric.Observe(LdapMetricDefinitions.ConcurrentRequests, concurrentRequests,
                new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
            _metric.Observe(LdapMetricDefinitions.RequestsTotal, 1,
                new LabelValues([nameof(LdapConnectionPool), _poolIdentifier]));
            
            if (result.IsSuccess)
                return (SearchResponse)result.Value;
            else
                throw new TimeoutException($"LDAP {request.Scope} query to '{request.DistinguishedName}' timed out after {timeout.TotalMilliseconds}ms.");
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SharpHoundCommonLib.Interfaces;
using SharpHoundCommonLib.Models;

namespace SharpHoundCommonLib.Services;

public sealed class FileMetricSink(
    IReadOnlyList<MetricDefinition> definitions,
    TextWriter textWriter,
    IMetricWriter metricWriter,
    FileMetricSinkOptions options = null)
    : IMetricSink, IDisposable {
    private readonly TextWriter _textWriter = textWriter;
    private readonly IMetricWriter _metricWriter = metricWriter;
    private readonly FileMetricSinkOptions _options = options ?? new FileMetricSinkOptions();
    
    
    // metric state, using a lock rather than a concurrent dictionary protects both the dictionary,
    // and the aggregators state.
    private readonly MetricDefinition[] _definitions = definitions.ToArray();
    private readonly Dictionary<(int, LabelValues), MetricAggregator> _states = new();
    private readonly object _lock = new();

    public FileMetricSink(
        IReadOnlyList<MetricDefinition> definitions,
        string filePath,
        IMetricWriter metricWriter,
        FileMetricSinkOptions options = null) 
    : this(
        definitions, 
        new StreamWriter(
            File.Open(filePath, FileMode.Create, FileAccess.Write, FileShare.Read)),
        metricWriter,
        options) {}

    public void Observe(in MetricObservation.DoubleMetricObservation observation) {
        var key = (observation.DefinitionId, observation.LabelsValues);

        lock (_lock) {
            if (!_states.TryGetValue(key, out var aggregator)) {
                aggregator = MetricAggregatorExtensions.Create(_definitions[observation.DefinitionId]);
                _states[key] = aggregator;
            }
            
            aggregator.Observe(observation.Value);
        }
    }

    private int EstimateSize() => _states.Count * 128;
    
    public void Flush() {
        string output;
        lock (_lock) {
            var sb = new StringBuilder(EstimateSize());
            
            var timestamp = DateTimeOffset.Now;
            sb.Append("Metric Flush: ")
                .Append(timestamp.ToString(_options.TimestampFormat))
                .AppendLine();
            sb.Append('=', 40).AppendLine();

            // Must use this deconstruction for .Net Version
            foreach (var kvp in _states) {
                var definitionId = kvp.Key.Item1;
                var labelValues = kvp.Key.Item2;
                var aggregator = kvp.Value;
                var definition = _definitions[definitionId];
                
                _metricWriter.StringBuilderAppendMetric(
                    sb,
                    definition,
                    labelValues,
                    aggregator,
                    timestamp);
            }

            sb.Append('=', 40).AppendLine().AppendLine().AppendLine().AppendLine().AppendLine();
            output = sb.ToString();
        }
        
        _textWriter.Write(output);

        if (_options.FlushWriter) 
            _textWriter.Flush();
    }
    
    public void Dispose() {
        _textWriter.Dispose();
    }
}
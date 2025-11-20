using Microsoft.ML;
using Microsoft.ML.Data;
using FraudDetection.ML.Models;

namespace FraudDetection.ML.Services;

public class ClusteringService
{
    private readonly MLContext _mlContext;
    private readonly ILogger<ClusteringService> _logger;
    private ITransformer? _model;
    private PredictionEngine<FraudFeatures, ClusterPrediction>? _predictionEngine;
    private readonly string _modelPath = "Models/clustering.zip";

    public ClusteringService(ILogger<ClusteringService> logger)
    {
        _mlContext = new MLContext(seed: 0);
        _logger = logger;

        if (File.Exists(_modelPath))
        {
            try
            {
                LoadModel();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load existing clustering model");
            }
        }
    }

    public async Task TrainModelAsync(List<FraudFeatures> trainingData)
    {
        await Task.Run(() =>
        {
            _logger.LogInformation("Training K-Means Clustering with {Count} sessions", trainingData.Count);

            if (trainingData.Count < 100)
            {
                _logger.LogWarning("Not enough data for clustering. Need at least 100 sessions.");
                return;
            }

            // Convert to IDataView
            // Note: ML.NET automatically uses only properties with [LoadColumn] attributes
            // Identifier properties (SessionId, ProfileId, DeviceKey, etc.) don't have [LoadColumn]
            // attributes, so they are automatically excluded from the ML schema
            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

            // Use key features for clustering
            var featureColumns = new[]
            {
                // Core behavioral features
                nameof(FraudFeatures.SessionDuration),
                nameof(FraudFeatures.EventCount),
                nameof(FraudFeatures.DeviceAgeInDays),
                nameof(FraudFeatures.OtpFailureCount),
                nameof(FraudFeatures.CardAdditionCount),
                nameof(FraudFeatures.P2PTransferCount),
                nameof(FraudFeatures.SessionStartHour),
                
                // Security features
                nameof(FraudFeatures.IsRooted),
                nameof(FraudFeatures.IsVpn),
                nameof(FraudFeatures.IsEmulator),
                
                // Historical patterns
                nameof(FraudFeatures.TotalSessionsForDevice),
                
                // Multi-accounting indicators
                nameof(FraudFeatures.UniqueUserIdsOnDevice_7d),
                nameof(FraudFeatures.UserSwitchesPerDay),
                
                // Multi-devicing indicators
                nameof(FraudFeatures.DevicesPerUser_7d),
                nameof(FraudFeatures.GeographicJumpCount_24h)
            };

            // Build pipeline with K-Means (5 clusters)
            /*var pipeline = _mlContext.Transforms
                .Concatenate("Features", featureColumns)
                .Append(_mlContext.Clustering.Trainers.KMeans(
                    featureColumnName: "Features",
                    numberOfClusters: 5,
                    optimizationTolerance: 1e-6f,
                    maximumNumberOfIterations: 100));*/

            var options = new Microsoft.ML.Trainers.KMeansTrainer.Options
            {
                FeatureColumnName = "Features",
                NumberOfClusters = 5,
                MaximumNumberOfIterations = 100,
                // Other options available:
                // InitializationAlgorithm = KMeansTrainer.InitializationAlgorithm.KMeansPlusPlus,
                // NumberOfThreads = null,
                // OptimizationTolerance is NOT available
            };

            var pipeline = _mlContext.Transforms
                .Concatenate("Features", featureColumns)
                .Append(_mlContext.Clustering.Trainers.KMeans(options));

            // Train
            _logger.LogInformation("Training K-Means clustering model...");
            _model = pipeline.Fit(dataView);

            // Save
            Directory.CreateDirectory(Path.GetDirectoryName(_modelPath)!);
            _mlContext.Model.Save(_model, dataView.Schema, _modelPath);

            _predictionEngine = _mlContext.Model
                .CreatePredictionEngine<FraudFeatures, ClusterPrediction>(_model);

            _logger.LogInformation("K-Means model trained and saved to {Path}", _modelPath);

            // Log cluster distribution
            var predictions = _model.Transform(dataView);
            var clusterData = _mlContext.Data.CreateEnumerable<ClusterPrediction>(predictions, false);
            var clusterCounts = clusterData.GroupBy(p => p.ClusterId).ToDictionary(g => g.Key, g => g.Count());

            _logger.LogInformation("Cluster Distribution:");
            foreach (var (clusterId, count) in clusterCounts.OrderBy(x => x.Key))
            {
                _logger.LogInformation("  Cluster {ClusterId}: {Count} sessions ({Percent:F1}%)",
                    clusterId, count, (float)count / trainingData.Count * 100);
            }
        });
    }

    public ClusterPrediction Predict(FraudFeatures features)
    {
        if (_predictionEngine == null)
        {
            _logger.LogWarning("Clustering model not loaded. Returning default.");
            return new ClusterPrediction { ClusterId = 0, Distances = Array.Empty<float>() };
        }

        try
        {
            return _predictionEngine.Predict(features);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error predicting cluster for session {SessionId}", features.SessionId);
            return new ClusterPrediction { ClusterId = 0, Distances = Array.Empty<float>() };
        }
    }

    public void LoadModel()
    {
        if (!File.Exists(_modelPath))
        {
            throw new FileNotFoundException($"Model file not found: {_modelPath}");
        }

        _model = _mlContext.Model.Load(_modelPath, out var schema);
        _predictionEngine = _mlContext.Model
            .CreatePredictionEngine<FraudFeatures, ClusterPrediction>(_model);

        _logger.LogInformation("K-Means model loaded from {Path}", _modelPath);
    }

    public bool IsModelLoaded => _predictionEngine != null;
}
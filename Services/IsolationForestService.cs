using Microsoft.ML;
using Microsoft.ML.Data;
using FraudDetection.ML.Models;

namespace FraudDetection.ML.Services;

public class IsolationForestService
{
    private readonly MLContext _mlContext;
    private readonly ILogger<IsolationForestService> _logger;
    private ITransformer? _model;
    private PredictionEngine<FraudFeatures, AnomalyPrediction>? _predictionEngine;
    private readonly string _modelPath = "Models/isolation_forest.zip";

    public IsolationForestService(ILogger<IsolationForestService> logger)
    {
        _mlContext = new MLContext(seed: 0);
        _logger = logger;

        // Load existing model if available
        if (File.Exists(_modelPath))
        {
            try
            {
                LoadModel();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load existing model, will train new one");
            }
        }
    }

    public async Task TrainModelAsync(List<FraudFeatures> trainingData)
    {
        await Task.Run(() =>
        {
            _logger.LogInformation("Training Isolation Forest with {Count} sessions", trainingData.Count);

            if (trainingData.Count < 100)
            {
                _logger.LogWarning("Not enough data for training. Need at least 100 sessions. Current: {Count}",
                    trainingData.Count);
                return;
            }

            // Convert to IDataView
            // Note: ML.NET automatically uses only properties with [LoadColumn] attributes
            // Identifier properties (SessionId, ProfileId, DeviceKey, etc.) don't have [LoadColumn]
            // attributes, so they are automatically excluded from the ML schema
            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

            // Define all feature columns (exclude identifiers)
            var featureColumns = new[]
            {
                // Session features
                nameof(FraudFeatures.SessionDuration),
                nameof(FraudFeatures.EventCount),
                nameof(FraudFeatures.AverageTimeBetweenEvents),
                nameof(FraudFeatures.SessionStartHour),
                nameof(FraudFeatures.DayOfWeek),
                nameof(FraudFeatures.SessionNumber),
                
                // Device features
                nameof(FraudFeatures.DeviceAgeInDays),
                nameof(FraudFeatures.InstallToSessionMinutes),
                nameof(FraudFeatures.BatteryLevel),
                nameof(FraudFeatures.RamFreeRatio),
                nameof(FraudFeatures.StorageFreeRatio),
                
                // Security features
                nameof(FraudFeatures.IsEmulator),
                nameof(FraudFeatures.IsRooted),
                nameof(FraudFeatures.IsVpn),
                nameof(FraudFeatures.IsCloned),
                nameof(FraudFeatures.IsRoaming),
                
                // Behavioral features
                nameof(FraudFeatures.OtpFailureCount),
                nameof(FraudFeatures.OtpSuccessCount),
                nameof(FraudFeatures.OtpSuccessRate),
                nameof(FraudFeatures.CardAdditionCount),
                nameof(FraudFeatures.P2PTransferCount),
                nameof(FraudFeatures.PaymentCount),
                nameof(FraudFeatures.TransferToPaymentRatio),
                
                // Historical features
                nameof(FraudFeatures.TotalSessionsForDevice),
                nameof(FraudFeatures.UniqueIpCount),
                nameof(FraudFeatures.DifferentCarrierCount),
                nameof(FraudFeatures.ConnectionIsMobile),
                
                // Multi-Accounting features
                nameof(FraudFeatures.UniqueUserIdsOnDevice_24h),
                nameof(FraudFeatures.UniqueUserIdsOnDevice_7d),
                nameof(FraudFeatures.UniqueUserIdsOnDevice_30d),
                nameof(FraudFeatures.UniquePhoneNumbersOnDevice_7d),
                nameof(FraudFeatures.UserSwitchesPerDay),
                nameof(FraudFeatures.NewUserCreationsOnDevice_24h),
                nameof(FraudFeatures.NewUserCreationsOnDevice_7d),
                nameof(FraudFeatures.AccountSwitchingVelocity),
                nameof(FraudFeatures.SameActionPatternScore),
                
                // Multi-Devicing features
                nameof(FraudFeatures.DevicesPerUser_24h),
                nameof(FraudFeatures.DevicesPerUser_7d),
                nameof(FraudFeatures.DevicesPerUser_30d),
                nameof(FraudFeatures.NewDeviceLoginsForUser_7d),
                nameof(FraudFeatures.DeviceSwitchesPerDayForUser),
                nameof(FraudFeatures.AlwaysNewDeviceFlag),
                nameof(FraudFeatures.GeographicJumpCount_24h),
                nameof(FraudFeatures.IpChangesForUser_24h),
                nameof(FraudFeatures.IpChangesForUser_7d),
                nameof(FraudFeatures.CarrierChangesForUser_7d),
                nameof(FraudFeatures.SuspiciousVelocityFlag)
            };

            // Build pipeline
            var pipeline = _mlContext.Transforms
                .Concatenate("Features", featureColumns)
                .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(
                    featureColumnName: "Features",
                    rank: 20,
                    ensureZeroMean: true,
                    oversampling: 20));

            // Train
            _logger.LogInformation("Training Isolation Forest model...");
            _model = pipeline.Fit(dataView);

            // Save model
            Directory.CreateDirectory(Path.GetDirectoryName(_modelPath)!);
            _mlContext.Model.Save(_model, dataView.Schema, _modelPath);

            // Create prediction engine
            _predictionEngine = _mlContext.Model
                .CreatePredictionEngine<FraudFeatures, AnomalyPrediction>(_model);

            _logger.LogInformation("Isolation Forest model trained and saved to {Path}", _modelPath);

            // Note: Cannot evaluate unsupervised anomaly detection model without labeled data
            // Evaluation requires a "Label" column with ground truth, which we don't have
            // The model performance will be assessed through real-world usage and monitoring
        });
    }

    public AnomalyPrediction Predict(FraudFeatures features)
    {
        if (_predictionEngine == null)
        {
            _logger.LogWarning("Model not loaded. Returning default prediction.");
            return new AnomalyPrediction { IsAnomaly = false, AnomalyScore = 0f };
        }

        try
        {
            var prediction = _predictionEngine.Predict(features);

            // Validate the prediction score
            if (float.IsNaN(prediction.AnomalyScore) || float.IsInfinity(prediction.AnomalyScore))
            {
                _logger.LogWarning("Model returned invalid AnomalyScore {Score} for session {SessionId}, setting to 0",
                    prediction.AnomalyScore, features.SessionId);
                prediction.AnomalyScore = 0f;
                prediction.IsAnomaly = false;
            }

            return prediction;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error predicting anomaly for session {SessionId}", features.SessionId);
            return new AnomalyPrediction { IsAnomaly = false, AnomalyScore = 0f };
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
            .CreatePredictionEngine<FraudFeatures, AnomalyPrediction>(_model);

        _logger.LogInformation("Isolation Forest model loaded from {Path}", _modelPath);
    }

    public bool IsModelLoaded => _predictionEngine != null;
}
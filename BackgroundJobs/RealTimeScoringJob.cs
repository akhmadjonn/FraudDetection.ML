using FraudDetection.ML.Services;
using FraudDetection.ML.Models;

namespace FraudDetection.ML.BackgroundJobs;

public class RealTimeScoringJob : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<RealTimeScoringJob> _logger;
    private DateTime _lastProcessedTime;
    private readonly TimeSpan _checkInterval;
    private readonly int _batchSize;

    public RealTimeScoringJob(
        IServiceProvider serviceProvider,
        ILogger<RealTimeScoringJob> logger,
        IConfiguration config)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _lastProcessedTime = DateTime.UtcNow.AddMinutes(-10);
        _checkInterval = TimeSpan.FromSeconds(config.GetValue<int>("ML:ScoringIntervalSeconds", 10));
        _batchSize = config.GetValue<int>("ML:ScoringBatchSize", 100);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Real-time Scoring Job started. Check interval: {Interval}", _checkInterval);

        // Wait for models to be trained
        await Task.Delay(TimeSpan.FromMinutes(6), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessNewSessionsAsync();
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Real-time scoring job cancelled");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in real-time scoring");
            }

            // Wait before next check
            await Task.Delay(_checkInterval, stoppingToken);
        }
    }

    private async Task ProcessNewSessionsAsync()
    {
        using var scope = _serviceProvider.CreateScope();
        var clickHouse = scope.ServiceProvider.GetRequiredService<ClickHouseService>();
        var featureService = scope.ServiceProvider.GetRequiredService<FeatureEngineeringService>();
        var isolationForest = scope.ServiceProvider.GetRequiredService<IsolationForestService>();
        var clustering = scope.ServiceProvider.GetRequiredService<ClusteringService>();
        var analysisService = scope.ServiceProvider.GetRequiredService<AnomalyAnalysisService>();
        var notification = scope.ServiceProvider.GetRequiredService<NotificationService>();
        var hybridAlert = scope.ServiceProvider.GetRequiredService<HybridAlertService>();

        // Check if models are loaded
        if (!isolationForest.IsModelLoaded || !clustering.IsModelLoaded)
        {
            _logger.LogWarning("ML models not loaded yet. Skipping scoring.");
            return;
        }

        // Get new sessions since last check
        var newSessions = await clickHouse.GetRecentSessionsAsync(
            _lastProcessedTime,
            limit: _batchSize);

        if (!newSessions.Any())
        {
            return;
        }

        _logger.LogInformation("Processing {Count} new sessions (from {From} to {To})",
            newSessions.Count,
            newSessions.Min(s => s.CreatedAt),
            newSessions.Max(s => s.CreatedAt));

        var processedCount = 0;
        var alertCount = 0;
        var throttledCount = 0;

        foreach (var session in newSessions)
        {
            try
            {
                // Extract features
                var features = await featureService.ExtractFeaturesAsync(session);
                if (features == null)
                {
                    _logger.LogWarning("Failed to extract features for session {SessionId}", session.SessionId);
                    continue;
                }

                // Get predictions from both models
                var anomalyPrediction = isolationForest.Predict(features);
                var clusterPrediction = clustering.Predict(features);

                // Analyze results
                var result = analysisService.AnalyzeSession(
                    features,
                    anomalyPrediction,
                    clusterPrediction);

                // ALWAYS save to database (regardless of alert status)
                await clickHouse.SaveAnalysisResultAsync(result);

                processedCount++;

                // Check for high-risk sessions and apply fraud-type-aware throttling
                if (result.RiskLevel is "CRITICAL" or "HIGH")
                {
                    // Use hybrid service to determine if alert should be sent
                    var decision = await hybridAlert.ShouldSendAlertAsync(result);

                    if (decision.ShouldSend)
                    {
                        // Send alert highlighting NEW fraud types
                        await notification.SendAlertAsync(result, decision.FraudTypesToAlert);

                        alertCount++;

                        _logger.LogWarning(
                            "🚨 {RiskLevel} alert sent! Session: {SessionId}, User: {Phone}, Score: {Score:F2}, NEW Fraud Types: {FraudTypes}, Reason: {Reason}",
                            result.RiskLevel,
                            result.SessionId,
                            result.PhoneNumber,
                            result.AnomalyScore,
                            string.Join(", ", decision.FraudTypesToAlert),
                            decision.Reason);
                    }
                    else
                    {
                        // All fraud types already alerted on - throttled
                        throttledCount++;

                        _logger.LogDebug(
                            "⏸️ Alert throttled for session {SessionId}. Reason: {Reason}. Detected: {All}, Throttled: {Throttled}",
                            result.SessionId,
                            decision.Reason,
                            string.Join(", ", decision.AllDetectedFraudTypes),
                            string.Join(", ", decision.ThrottledFraudTypes));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing session {SessionId}", session.SessionId);
            }
        }

        if (processedCount > 0)
        {
            _logger.LogInformation(
                "Processed {Processed}/{Total} sessions. Alerts sent: {Alerts}, Throttled: {Throttled}",
                processedCount,
                newSessions.Count,
                alertCount,
                throttledCount);
        }

        _lastProcessedTime = newSessions.Max(s => s.CreatedAt);
    }
}
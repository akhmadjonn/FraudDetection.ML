using FraudDetection.ML.Services;

namespace FraudDetection.ML.BackgroundJobs;

public class DailyAnalysisJob : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<DailyAnalysisJob> _logger;
    private readonly TimeSpan _dailyReportTime;

    public DailyAnalysisJob(
        IServiceProvider serviceProvider,
        ILogger<DailyAnalysisJob> logger,
        IConfiguration config)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;

        var reportHour = config.GetValue<int>("ML:DailyReportHour", 8);
        _dailyReportTime = TimeSpan.FromHours(reportHour);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Daily Analysis Job started. Report time: {Time}:00", _dailyReportTime.Hours);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.Now;
                var today = now.Date;
                var nextRun = today.Add(_dailyReportTime);

                // If we've passed today's report time, schedule for tomorrow
                if (now.TimeOfDay >= _dailyReportTime)
                {
                    nextRun = today.AddDays(1).Add(_dailyReportTime);
                }

                var delay = nextRun - now;

                _logger.LogInformation("Next daily report scheduled at {Time} (in {Delay})",
                    nextRun,
                    delay);

                await Task.Delay(delay, stoppingToken);

                await GenerateDailyReportAsync();
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Daily analysis job cancelled");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in daily analysis job");
                // Wait 1 hour before retry
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
            }
        }
    }

    private async Task GenerateDailyReportAsync()
    {
        _logger.LogInformation("═══════════════════════════════════════");
        _logger.LogInformation("Generating daily analysis report...");
        _logger.LogInformation("═══════════════════════════════════════");

        try
        {
            using var scope = _serviceProvider.CreateScope();
            var analysisService = scope.ServiceProvider.GetRequiredService<AnomalyAnalysisService>();
            var notification = scope.ServiceProvider.GetRequiredService<NotificationService>();

            // Generate report for yesterday
            var reportDate = DateTime.UtcNow.Date.AddDays(-1);

            _logger.LogInformation("Analyzing data for {Date}", reportDate.ToString("yyyy-MM-dd"));

            var report = await analysisService.GenerateReportAsync(reportDate);

            // Log summary
            _logger.LogInformation("Report Summary:");
            _logger.LogInformation("  Total Sessions: {Total}", report.TotalSessionsAnalyzed);
            _logger.LogInformation("  Critical: {Critical} ({Percent:F1}%)",
                report.CriticalCount,
                GetPercentage(report.CriticalCount, report.TotalSessionsAnalyzed));
            _logger.LogInformation("  High: {High} ({Percent:F1}%)",
                report.HighCount,
                GetPercentage(report.HighCount, report.TotalSessionsAnalyzed));
            _logger.LogInformation("  Multi-Accounting Cases: {Count}", report.MultiAccountingCount);
            _logger.LogInformation("  Multi-Devicing Cases: {Count}", report.MultiDevicingCount);
            _logger.LogInformation("  Account Takeover Cases: {Count}", report.AccountTakeoverCount);
            _logger.LogInformation("  Patterns Found: {Count}", report.PatternsFound.Count);

            // Send report via Teams/Telegram
            await notification.SendDailyReportAsync(report);

            _logger.LogInformation("═══════════════════════════════════════");
            _logger.LogInformation("Daily report generated and sent successfully!");
            _logger.LogInformation("═══════════════════════════════════════");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating daily report");
        }
    }

    private float GetPercentage(int count, int total)
    {
        return total > 0 ? (float)count / total * 100 : 0f;
    }
}
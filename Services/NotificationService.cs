using FraudDetection.ML.Models;
using System.Net.Http.Json;
using System.Text;

namespace FraudDetection.ML.Services;

public class NotificationService
{
    private readonly ILogger<NotificationService> _logger;
    private readonly HttpClient _httpClient;
    private readonly string? _teamsWebhookUrl;
    private readonly string? _telegramBotToken;
    private readonly string? _telegramChatId;

    public NotificationService(
        IConfiguration config,
        ILogger<NotificationService> logger,
        HttpClient httpClient)
    {
        _logger = logger;
        _httpClient = httpClient;
        _teamsWebhookUrl = config["Notifications:TeamsWebhook"];
        _telegramBotToken = config["Notifications:TelegramBotToken"];
        _telegramChatId = config["Notifications:TelegramChatId"];
    }

    public async Task SendAlertAsync(FraudAnalysisResult result)
    {
        var message = FormatAlert(result);

        // Send to Teams
        if (!string.IsNullOrEmpty(_teamsWebhookUrl))
        {
            await SendToTeamsAsync(message, result.RiskLevel);
        }

        // Send to Telegram for CRITICAL only
        if (result.RiskLevel == "CRITICAL" && !string.IsNullOrEmpty(_telegramBotToken))
        {
            await SendToTelegramAsync(message);
        }
    }

    public async Task SendDailyReportAsync(DailyAnalysisReport report)
    {
        var message = FormatDailyReport(report);

        if (!string.IsNullOrEmpty(_teamsWebhookUrl))
        {
            await SendToTeamsAsync(message, "INFO");
        }

        if (!string.IsNullOrEmpty(_telegramBotToken))
        {
            await SendToTelegramAsync(message);
        }
    }

    private string FormatAlert(FraudAnalysisResult result)
    {
        var sb = new StringBuilder();

        var emoji = result.RiskLevel switch
        {
            "CRITICAL" => "🚨",
            "HIGH" => "⚠️",
            "MEDIUM" => "🟡",
            _ => "ℹ️"
        };

        sb.AppendLine($"{emoji} **{result.RiskLevel} RISK ALERT**");
        sb.AppendLine();
        sb.AppendLine("**Session Details:**");
        sb.AppendLine($"• Session: `{result.SessionId}`");
        sb.AppendLine($"• User: {result.PhoneNumber}");
        sb.AppendLine($"• Device: `{result.DeviceKey}`");
        sb.AppendLine($"• Anomaly Score: **{result.AnomalyScore:F2}**");
        sb.AppendLine($"• Cluster: {result.ClusterId}");
        sb.AppendLine();

        // Fraud Types
        var fraudTypes = new List<string>();
        if (result.IsMultiAccounting) fraudTypes.Add("Multi-Accounting");
        if (result.IsMultiDevicing) fraudTypes.Add("Multi-Devicing");
        if (result.IsAccountTakeover) fraudTypes.Add("Account Takeover");
        if (result.IsImpossibleTravel) fraudTypes.Add("Impossible Travel");

        if (fraudTypes.Any())
        {
            sb.AppendLine("**🎯 Fraud Types Detected:**");
            foreach (var type in fraudTypes)
            {
                sb.AppendLine($"• {type}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("**🔍 Suspicious Indicators:**");
        foreach (var reason in result.SuspiciousReasons.Take(5))
        {
            sb.AppendLine($"• {reason}");
        }

        if (result.SuspiciousReasons.Count > 5)
        {
            sb.AppendLine($"• ... and {result.SuspiciousReasons.Count - 5} more reasons");
        }

        sb.AppendLine();
        sb.AppendLine("**📊 Key Metrics:**");
        sb.AppendLine($"• Device Age: {result.Features.DeviceAgeInDays:F1} days");
        sb.AppendLine($"• OTP Failures: {result.Features.OtpFailureCount}");
        sb.AppendLine($"• Card Additions: {result.Features.CardAdditionCount}");
        sb.AppendLine($"• P2P Transfers: {result.Features.P2PTransferCount}");

        if (result.IsMultiAccounting)
        {
            sb.AppendLine($"• Users on Device (7d): {result.Features.UniqueUserIdsOnDevice_7d}");
        }

        if (result.IsMultiDevicing)
        {
            sb.AppendLine($"• Devices Used (7d): {result.Features.DevicesPerUser_7d}");
        }

        return sb.ToString();
    }

    private string FormatDailyReport(DailyAnalysisReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"📊 **DAILY FRAUD DETECTION REPORT**");
        sb.AppendLine($"**Date:** {report.ReportDate:yyyy-MM-dd}");
        sb.AppendLine();
        sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        sb.AppendLine();

        // Summary
        sb.AppendLine($"**📈 Total Sessions Analyzed:** {report.TotalSessionsAnalyzed:N0}");
        sb.AppendLine();

        // Risk Distribution
        sb.AppendLine("**⚡ Risk Distribution:**");
        sb.AppendLine($"🚨 Critical: **{report.CriticalCount}** ({GetPercentage(report.CriticalCount, report.TotalSessionsAnalyzed):F1}%)");
        sb.AppendLine($"⚠️  High: **{report.HighCount}** ({GetPercentage(report.HighCount, report.TotalSessionsAnalyzed):F1}%)");
        sb.AppendLine($"🟡 Medium: **{report.MediumCount}** ({GetPercentage(report.MediumCount, report.TotalSessionsAnalyzed):F1}%)");
        sb.AppendLine($"🟢 Low: **{report.LowCount}** ({GetPercentage(report.LowCount, report.TotalSessionsAnalyzed):F1}%)");
        sb.AppendLine();

        // Fraud Types
        sb.AppendLine("**🎯 Fraud Types Detected:**");
        sb.AppendLine($"• Multi-Accounting: **{report.MultiAccountingCount}** cases");
        sb.AppendLine($"• Multi-Devicing: **{report.MultiDevicingCount}** cases");
        sb.AppendLine($"• Account Takeover: **{report.AccountTakeoverCount}** cases");
        sb.AppendLine($"• Impossible Travel: **{report.ImpossibleTravelCount}** cases");
        sb.AppendLine();

        // Top Multi-Accounting Devices
        if (report.TopMultiAccountingDevices.Any())
        {
            sb.AppendLine("**🔴 Top Multi-Accounting Devices:**");
            foreach (var device in report.TopMultiAccountingDevices.Take(3))
            {
                sb.AppendLine($"• Device `{device.DeviceKey}`: **{device.UniqueUserCount}** different users");
                sb.AppendLine($"  Risk Score: {device.RiskScore:F2} | Active: {device.FirstSeen:MM/dd} - {device.LastSeen:MM/dd}");
            }
            sb.AppendLine();
        }

        // Top Multi-Devicing Users
        if (report.TopMultiDevicingUsers.Any())
        {
            sb.AppendLine("**🔴 Top Multi-Devicing Users:**");
            foreach (var user in report.TopMultiDevicingUsers.Take(3))
            {
                sb.AppendLine($"• User {user.PhoneNumber}: **{user.UniqueDeviceCount}** different devices");
                if (user.HasImpossibleTravel)
                {
                    sb.AppendLine($"  ⚠️ Impossible Travel Detected! ({user.GeographicJumps} jumps)");
                }
                sb.AppendLine($"  Risk Score: {user.RiskScore:F2}");
            }
            sb.AppendLine();
        }

        // Suspicious Patterns
        if (report.PatternsFound.Any())
        {
            sb.AppendLine("**🔍 Suspicious Patterns Detected:**");
            sb.AppendLine();

            foreach (var pattern in report.PatternsFound.Take(3))
            {
                sb.AppendLine($"**{pattern.PatternName}** ({pattern.OccurrenceCount} occurrences)");
                sb.AppendLine($"_{pattern.Description}_");
                sb.AppendLine();
                sb.AppendLine("Characteristics:");
                foreach (var characteristic in pattern.CommonCharacteristics.Take(3))
                {
                    sb.AppendLine($"  • {characteristic}");
                }
                sb.AppendLine();
                sb.AppendLine($"**→ Recommended Action:** {pattern.RecommendedAction}");
                sb.AppendLine();
                sb.AppendLine("───────────────────────");
                sb.AppendLine();
            }
        }

        // Cluster Analysis
        sb.AppendLine("**📊 Cluster Analysis:**");
        foreach (var cluster in report.ClusterSummaries.Take(3))
        {
            var icon = cluster.IsSuspicious ? "⚠️" : "✅";
            sb.AppendLine($"{icon} **Cluster {cluster.ClusterId}:** {cluster.SessionCount:N0} sessions ({cluster.PercentageOfTotal:F1}%)");
            sb.AppendLine($"   _{cluster.Interpretation}_");
        }

        return sb.ToString();
    }

    private float GetPercentage(int count, int total)
    {
        return total > 0 ? (float)count / total * 100 : 0f;
    }

    private async Task SendToTeamsAsync(string message, string severity)
    {
        if (string.IsNullOrEmpty(_teamsWebhookUrl)) return;

        try
        {
            var color = severity switch
            {
                "CRITICAL" => "FF0000",
                "HIGH" => "FFA500",
                "MEDIUM" => "FFFF00",
                _ => "0078D4"
            };

            var payload = new
            {
                type = "message",
                attachments = new[]
                {
                    new
                    {
                        contentType = "application/vnd.microsoft.card.adaptive",
                        content = new
                        {
                            type = "AdaptiveCard",
                            body = new[]
                            {
                                new
                                {
                                    type = "TextBlock",
                                    text = message,
                                    wrap = true
                                }
                            },
                            msteams = new
                            {
                                width = "Full"
                            }
                        }
                    }
                }
            };

            var response = await _httpClient.PostAsJsonAsync(_teamsWebhookUrl, payload);
            response.EnsureSuccessStatusCode();

            _logger.LogInformation("Notification sent to Teams");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send Teams notification");
        }
    }

    private async Task SendToTelegramAsync(string message)
    {
        if (string.IsNullOrEmpty(_telegramBotToken) || string.IsNullOrEmpty(_telegramChatId))
            return;

        try
        {
            var url = $"https://api.telegram.org/bot{_telegramBotToken}/sendMessage";
            var payload = new
            {
                chat_id = _telegramChatId,
                text = message,
                parse_mode = "Markdown"
            };

            var response = await _httpClient.PostAsJsonAsync(url, payload);
            response.EnsureSuccessStatusCode();

            _logger.LogInformation("Notification sent to Telegram");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send Telegram notification");
        }
    }
}
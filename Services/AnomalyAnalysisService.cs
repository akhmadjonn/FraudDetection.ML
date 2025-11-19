using FraudDetection.ML.Models;

namespace FraudDetection.ML.Services;

public class AnomalyAnalysisService
{
    private readonly ILogger<AnomalyAnalysisService> _logger;
    private readonly ClickHouseService _clickHouse;

    public AnomalyAnalysisService(
        ILogger<AnomalyAnalysisService> logger,
        ClickHouseService clickHouse)
    {
        _logger = logger;
        _clickHouse = clickHouse;
    }

    public FraudAnalysisResult AnalyzeSession(
        FraudFeatures features,
        AnomalyPrediction anomaly,
        ClusterPrediction cluster)
    {
        var suspiciousReasons = new List<string>();
        bool isMultiAccounting = false;
        bool isMultiDevicing = false;
        bool isAccountTakeover = false;
        bool isImpossibleTravel = false;

        // ==================== SECURITY CHECKS ====================
        if (features.IsRooted == 1)
            suspiciousReasons.Add("Rooted/Jailbroken device detected");

        if (features.IsEmulator == 1)
            suspiciousReasons.Add("Running on emulator");

        if (features.IsCloned == 1)
            suspiciousReasons.Add("Cloned app detected");

        if (features.IsVpn == 1)
            suspiciousReasons.Add("VPN connection detected");

        // ==================== DEVICE AGE CHECKS ====================
        if (features.DeviceAgeInDays < 1)
            suspiciousReasons.Add($"Very new device ({features.DeviceAgeInDays:F1} hours old)");

        if (features.InstallToSessionMinutes < 30 && features.CardAdditionCount > 0)
            suspiciousReasons.Add("Card added within 30 minutes of app installation");

        // ==================== OTP CHECKS ====================
        if (features.OtpFailureCount >= 3)
            suspiciousReasons.Add($"Multiple OTP failures ({features.OtpFailureCount})");

        if (features.OtpSuccessRate < 0.5f && features.OtpFailureCount > 0)
            suspiciousReasons.Add($"Low OTP success rate ({features.OtpSuccessRate:P0})");

        // ==================== BEHAVIORAL CHECKS ====================
        if (features.CardAdditionCount >= 2)
            suspiciousReasons.Add($"Multiple cards added in session ({features.CardAdditionCount})");

        if (features.SessionStartHour >= 2 && features.SessionStartHour <= 5)
            suspiciousReasons.Add("Unusual activity time (2-5 AM)");

        if (features.SessionDuration > 0 && features.SessionDuration < 1 &&
            (features.P2PTransferCount > 0 || features.CardAdditionCount > 0))
            suspiciousReasons.Add("Very short session with sensitive actions");

        // ==================== MULTI-ACCOUNTING DETECTION ====================
        if (features.UniqueUserIdsOnDevice_24h >= 3)
        {
            isMultiAccounting = true;
            suspiciousReasons.Add($"⚠️ MULTI-ACCOUNTING: {features.UniqueUserIdsOnDevice_24h} different users on device in 24h");
        }

        if (features.UniqueUserIdsOnDevice_7d >= 5)
        {
            isMultiAccounting = true;
            suspiciousReasons.Add($"⚠️ MULTI-ACCOUNTING: {features.UniqueUserIdsOnDevice_7d} different users on device in 7 days");
        }

        if (features.UserSwitchesPerDay >= 3)
        {
            isMultiAccounting = true;
            suspiciousReasons.Add($"⚠️ MULTI-ACCOUNTING: Rapid account switching ({features.UserSwitchesPerDay:F1} switches/day)");
        }

        if (features.NewUserCreationsOnDevice_24h >= 2)
        {
            isMultiAccounting = true;
            suspiciousReasons.Add($"⚠️ MULTI-ACCOUNTING: {features.NewUserCreationsOnDevice_24h} new accounts created on device in 24h");
        }

        if (features.SameActionPatternScore > 0.8f && features.UniqueUserIdsOnDevice_7d >= 3)
        {
            isMultiAccounting = true;
            suspiciousReasons.Add("⚠️ MULTI-ACCOUNTING: All accounts show identical behavior pattern");
        }

        // ==================== MULTI-DEVICING DETECTION ====================
        if (features.DevicesPerUser_24h >= 3)
        {
            isMultiDevicing = true;
            suspiciousReasons.Add($"⚠️ MULTI-DEVICING: User on {features.DevicesPerUser_24h} different devices in 24h");
        }

        if (features.DevicesPerUser_7d >= 5)
        {
            isMultiDevicing = true;
            suspiciousReasons.Add($"⚠️ MULTI-DEVICING: User on {features.DevicesPerUser_7d} different devices in 7 days");
        }

        if (features.NewDeviceLoginsForUser_7d >= 3)
        {
            isMultiDevicing = true;
            suspiciousReasons.Add($"⚠️ MULTI-DEVICING: {features.NewDeviceLoginsForUser_7d} new device logins in 7 days");
        }

        if (features.AlwaysNewDeviceFlag == 1)
        {
            isAccountTakeover = true;
            suspiciousReasons.Add("⚠️ ACCOUNT TAKEOVER: User always on brand new devices");
        }

        // ==================== IMPOSSIBLE TRAVEL ====================
        if (features.GeographicJumpCount_24h >= 1)
        {
            isImpossibleTravel = true;
            suspiciousReasons.Add($"⚠️ IMPOSSIBLE TRAVEL: {features.GeographicJumpCount_24h} geographic jumps detected in 24h");
        }

        if (features.SuspiciousVelocityFlag == 1)
        {
            isImpossibleTravel = true;
            isAccountTakeover = true;
            suspiciousReasons.Add("⚠️ IMPOSSIBLE TRAVEL: User appeared in different locations impossibly fast");
        }

        if (features.CarrierChangesForUser_7d >= 3)
        {
            isMultiDevicing = true;
            suspiciousReasons.Add($"Multiple carrier changes ({features.CarrierChangesForUser_7d} in 7 days)");
        }

        // ==================== DETERMINE RISK LEVEL ====================
        var riskLevel = DetermineRiskLevel(
            anomaly.AnomalyScore,
            suspiciousReasons.Count,
            isMultiAccounting,
            isMultiDevicing,
            isAccountTakeover,
            isImpossibleTravel,
            features);

        return new FraudAnalysisResult
        {
            SessionId = features.SessionId,
            ProfileId = features.ProfileId,
            DeviceKey = features.DeviceKey,
            GlobalDeviceId = features.GlobalDeviceId,
            UserId = features.UserId,
            PhoneNumber = features.PhoneNumber,
            AnalyzedAt = DateTime.UtcNow,
            AnomalyScore = anomaly.AnomalyScore,
            IsAnomaly = anomaly.IsAnomaly,
            ClusterId = cluster.ClusterId,
            RiskLevel = riskLevel,
            IsMultiAccounting = isMultiAccounting,
            IsMultiDevicing = isMultiDevicing,
            IsAccountTakeover = isAccountTakeover,
            IsImpossibleTravel = isImpossibleTravel,
            SuspiciousReasons = suspiciousReasons,
            Features = features
        };
    }

    private string DetermineRiskLevel(
        float anomalyScore,
        int reasonCount,
        bool isMultiAccounting,
        bool isMultiDevicing,
        bool isAccountTakeover,
        bool isImpossibleTravel,
        FraudFeatures features)
    {
        // CRITICAL: Severe fraud indicators
        if (isMultiAccounting && features.UniqueUserIdsOnDevice_24h >= 5)
            return "CRITICAL";

        if (isAccountTakeover && isImpossibleTravel)
            return "CRITICAL";

        if (features.IsEmulator == 1 && features.IsRooted == 1 && features.DeviceAgeInDays < 1)
            return "CRITICAL";

        if (anomalyScore >= 0.85 || reasonCount >= 5)
            return "CRITICAL";

        // HIGH: Multiple red flags
        if (isMultiAccounting || isMultiDevicing)
            return "HIGH";

        if (anomalyScore >= 0.7 || reasonCount >= 3)
            return "HIGH";

        // MEDIUM: Some concerns
        if (anomalyScore >= 0.5 || reasonCount >= 2)
            return "MEDIUM";

        if (features.DeviceAgeInDays < 1 && (features.CardAdditionCount > 0 || features.P2PTransferCount > 0))
            return "MEDIUM";

        // LOW: Minor concerns or normal
        return "LOW";
    }

    public async Task<DailyAnalysisReport> GenerateReportAsync(DateTime reportDate)
    {
        _logger.LogInformation("Generating daily analysis report for {Date}", reportDate);

        var fromDate = reportDate.Date;
        var toDate = reportDate.Date.AddDays(1);

        var results = await _clickHouse.GetAnalysisResultsAsync(fromDate, toDate);

        var report = new DailyAnalysisReport
        {
            ReportDate = reportDate,
            TotalSessionsAnalyzed = results.Count,
            CriticalCount = results.Count(r => r.RiskLevel == "CRITICAL"),
            HighCount = results.Count(r => r.RiskLevel == "HIGH"),
            MediumCount = results.Count(r => r.RiskLevel == "MEDIUM"),
            LowCount = results.Count(r => r.RiskLevel == "LOW"),
            MultiAccountingCount = results.Count(r => r.IsMultiAccounting),
            MultiDevicingCount = results.Count(r => r.IsMultiDevicing),
            AccountTakeoverCount = results.Count(r => r.IsAccountTakeover),
            ImpossibleTravelCount = results.Count(r => r.IsImpossibleTravel),
            PatternsFound = FindPatterns(results),
            ClusterSummaries = AnalyzeClusters(results),
            TopSuspiciousSessions = results.OrderByDescending(r => r.AnomalyScore).Take(10).ToList(),
            TopMultiAccountingDevices = await _clickHouse.GetTopMultiAccountingDevicesAsync(fromDate, 10),
            TopMultiDevicingUsers = await _clickHouse.GetTopMultiDevicingUsersAsync(fromDate, 10)
        };

        return report;
    }

    private List<SuspiciousPattern> FindPatterns(List<FraudAnalysisResult> results)
    {
        var patterns = new List<SuspiciousPattern>();
        var suspicious = results.Where(r => r.RiskLevel is "CRITICAL" or "HIGH").ToList();

        if (!suspicious.Any()) return patterns;

        // Pattern 1: Multi-Accounting Farms
        var multiAccountingCases = suspicious.Where(r => r.IsMultiAccounting).ToList();
        if (multiAccountingCases.Any())
        {
            patterns.Add(new SuspiciousPattern
            {
                PatternName = "Multi-Accounting Farms",
                Description = "Devices being used by multiple different user accounts",
                OccurrenceCount = multiAccountingCases.Count,
                CommonCharacteristics = new List<string>
                {
                    $"Average users per device: {multiAccountingCases.Average(p => p.Features.UniqueUserIdsOnDevice_7d):F1}",
                    $"Devices with 5+ accounts: {multiAccountingCases.Count(p => p.Features.UniqueUserIdsOnDevice_7d >= 5)}",
                    $"New account creation rate: {multiAccountingCases.Average(p => p.Features.NewUserCreationsOnDevice_24h):F1} per day",
                    $"Rooted devices: {multiAccountingCases.Count(p => p.Features.IsRooted == 1)} ({(float)multiAccountingCases.Count(p => p.Features.IsRooted == 1) / multiAccountingCases.Count * 100:F0}%)"
                },
                RecommendedAction = "Block devices with 5+ accounts in 24 hours. Require device verification for accounts on shared devices."
            });
        }

        // Pattern 2: Account Takeover / Credential Stuffing
        var accountTakeoverCases = suspicious.Where(r => r.IsAccountTakeover).ToList();
        if (accountTakeoverCases.Any())
        {
            patterns.Add(new SuspiciousPattern
            {
                PatternName = "Account Takeover / Credential Stuffing",
                Description = "User accounts appearing on many brand new devices",
                OccurrenceCount = accountTakeoverCases.Count,
                CommonCharacteristics = new List<string>
                {
                    $"Average devices per user: {accountTakeoverCases.Average(p => p.Features.DevicesPerUser_7d):F1}",
                    $"New device logins: {accountTakeoverCases.Sum(p => p.Features.NewDeviceLoginsForUser_7d)}",
                    $"Cases with impossible travel: {accountTakeoverCases.Count(p => p.IsImpossibleTravel)}",
                    $"VPN usage: {accountTakeoverCases.Count(p => p.Features.IsVpn == 1)} ({(float)accountTakeoverCases.Count(p => p.Features.IsVpn == 1) / accountTakeoverCases.Count * 100:F0}%)"
                },
                RecommendedAction = "Freeze accounts showing impossible travel. Require 2FA verification for new device logins."
            });
        }

        // Pattern 3: Night Raiders
        var nightPattern = suspicious.Where(r =>
            r.Features.SessionStartHour >= 2 && r.Features.SessionStartHour <= 5).ToList();
        if (nightPattern.Any())
        {
            patterns.Add(new SuspiciousPattern
            {
                PatternName = "Night Raiders",
                Description = "Suspicious activity during unusual hours (2-5 AM)",
                OccurrenceCount = nightPattern.Count,
                CommonCharacteristics = new List<string>
                {
                    $"Average session duration: {nightPattern.Average(p => p.Features.SessionDuration):F1} minutes",
                    $"P2P transfers: {nightPattern.Sum(p => p.Features.P2PTransferCount)}",
                    $"Card additions: {nightPattern.Sum(p => p.Features.CardAdditionCount)}",
                    $"VPN usage: {nightPattern.Count(p => p.Features.IsVpn == 1)} ({(float)nightPattern.Count(p => p.Features.IsVpn == 1) / nightPattern.Count * 100:F0}%)"
                },
                RecommendedAction = "Add extra verification steps for high-risk transactions between 2-5 AM."
            });
        }

        // Pattern 4: OTP Brute Force
        var otpPattern = suspicious.Where(r => r.Features.OtpFailureCount >= 3).ToList();
        if (otpPattern.Any())
        {
            patterns.Add(new SuspiciousPattern
            {
                PatternName = "OTP Brute Force Attempts",
                Description = "Multiple OTP failures indicating potential brute force attacks",
                OccurrenceCount = otpPattern.Count,
                CommonCharacteristics = new List<string>
                {
                    $"Average OTP failures: {otpPattern.Average(p => p.Features.OtpFailureCount):F1}",
                    $"Success rate: {otpPattern.Average(p => p.Features.OtpSuccessRate):P0}",
                    $"Emulator usage: {otpPattern.Count(p => p.Features.IsEmulator == 1)}",
                    $"Rooted devices: {otpPattern.Count(p => p.Features.IsRooted == 1)}"
                },
                RecommendedAction = "Implement progressive delays and temporary lockout after 3 failed OTP attempts."
            });
        }

        // Pattern 5: New Device Rush
        var newDevicePattern = suspicious.Where(r =>
            r.Features.DeviceAgeInDays < 1 && r.Features.CardAdditionCount >= 1).ToList();
        if (newDevicePattern.Any())
        {
            patterns.Add(new SuspiciousPattern
            {
                PatternName = "New Device Rush",
                Description = "Brand new devices immediately adding cards",
                OccurrenceCount = newDevicePattern.Count,
                CommonCharacteristics = new List<string>
                {
                    $"Average device age: {newDevicePattern.Average(p => p.Features.DeviceAgeInDays * 24):F1} hours",
                    $"Average time to first action: {newDevicePattern.Average(p => p.Features.InstallToSessionMinutes):F0} minutes",
                    $"Cards added: {newDevicePattern.Sum(p => p.Features.CardAdditionCount)}",
                    $"Rooted/Cloned: {newDevicePattern.Count(p => p.Features.IsRooted == 1 || p.Features.IsCloned == 1)}"
                },
                RecommendedAction = "Add cooling period (24h) for sensitive actions on new device installations."
            });
        }

        return patterns.OrderByDescending(p => p.OccurrenceCount).ToList();
    }

    private List<ClusterSummary> AnalyzeClusters(List<FraudAnalysisResult> results)
    {
        var clusterGroups = results.GroupBy(r => r.ClusterId);
        var summaries = new List<ClusterSummary>();

        foreach (var group in clusterGroups)
        {
            var sessions = group.ToList();

            var avgFeatures = new Dictionary<string, float>
            {
                ["DeviceAge"] = sessions.Average(s => s.Features.DeviceAgeInDays),
                ["SessionDuration"] = sessions.Average(s => s.Features.SessionDuration),
                ["EventCount"] = sessions.Average(s => s.Features.EventCount),
                ["OtpFailures"] = sessions.Average(s => s.Features.OtpFailureCount),
                ["CardAdditions"] = sessions.Average(s => s.Features.CardAdditionCount),
                ["P2PTransfers"] = sessions.Average(s => s.Features.P2PTransferCount),
                ["RootedPercent"] = sessions.Average(s => s.Features.IsRooted) * 100,
                ["UniqueUsersOnDevice"] = sessions.Average(s => s.Features.UniqueUserIdsOnDevice_7d),
                ["DevicesPerUser"] = sessions.Average(s => s.Features.DevicesPerUser_7d)
            };

            var suspiciousCount = sessions.Count(s => s.RiskLevel is "CRITICAL" or "HIGH");
            var suspiciousPercent = (float)suspiciousCount / sessions.Count * 100;

            var interpretation = InterpretCluster(avgFeatures, suspiciousPercent, sessions);

            summaries.Add(new ClusterSummary
            {
                ClusterId = group.Key,
                SessionCount = sessions.Count,
                PercentageOfTotal = (float)sessions.Count / results.Count * 100,
                AverageFeatures = avgFeatures,
                Interpretation = interpretation,
                IsSuspicious = suspiciousPercent > 30
            });
        }

        return summaries.OrderByDescending(s => s.SessionCount).ToList();
    }

    private string InterpretCluster(
        Dictionary<string, float> features,
        float suspiciousPercent,
        List<FraudAnalysisResult> sessions)
    {
        var multiAccountingCount = sessions.Count(s => s.IsMultiAccounting);
        var multiDevicingCount = sessions.Count(s => s.IsMultiDevicing);

        // Multi-Accounting Cluster
        if (multiAccountingCount > sessions.Count * 0.5)
        {
            return $"⚠️ MULTI-ACCOUNTING CLUSTER ({suspiciousPercent:F0}% suspicious) - " +
                   $"Avg {features["UniqueUsersOnDevice"]:F1} users per device. IMMEDIATE ACTION REQUIRED!";
        }

        // Account Takeover Cluster
        if (multiDevicingCount > sessions.Count * 0.5)
        {
            return $"⚠️ ACCOUNT TAKEOVER CLUSTER ({suspiciousPercent:F0}% suspicious) - " +
                   $"Avg {features["DevicesPerUser"]:F1} devices per user. Possible credential stuffing.";
        }

        // High Risk Cluster
        if (suspiciousPercent > 50)
        {
            return $"🚨 HIGH RISK CLUSTER ({suspiciousPercent:F0}% suspicious) - Requires immediate review";
        }

        // Normal Users
        if (features["DeviceAge"] > 60 && features["OtpFailures"] < 0.5 && suspiciousPercent < 10)
        {
            return "✅ Normal Users - Established devices with good behavior";
        }

        // Power Users
        if (features["P2PTransfers"] > 3 && features["DeviceAge"] > 30 && suspiciousPercent < 20)
        {
            return "💰 Power Users - Frequent legitimate transactions";
        }

        // New Users
        if (features["DeviceAge"] < 7)
        {
            return $"🆕 New Users - Recent installations ({suspiciousPercent:F0}% flagged for review)";
        }

        return $"Mixed behavior cluster ({suspiciousPercent:F0}% suspicious)";
    }
}
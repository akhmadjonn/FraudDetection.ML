using System.Collections.Concurrent;
using FraudDetection.ML.Models;

namespace FraudDetection.ML.Services;

/// <summary>
/// Hybrid alert throttling service combining fast in-memory checks with optional database persistence.
/// Detects 8 fraud types and tracks each independently to prevent duplicate alerts while never missing new patterns.
/// </summary>
public class HybridAlertService
{
    private readonly ConcurrentDictionary<string, ThrottleEntry> _throttleCache = new();
    private readonly ILogger<HybridAlertService> _logger;
    private readonly AlertHistoryService? _historyService;
    private readonly IConfiguration _config;
    private readonly bool _enableDatabasePersistence;
    private readonly TimeSpan _defaultThrottleWindow;
    private readonly Dictionary<string, FraudTypeConfig> _fraudTypeConfigs;

    public HybridAlertService(
        ILogger<HybridAlertService> logger,
        IConfiguration config,
        AlertHistoryService historyService)
    {
        _logger = logger;
        _config = config;
        _historyService = historyService;

        // Load configuration
        _enableDatabasePersistence = config.GetValue<bool>("Alerts:EnableDatabasePersistence", true);
        var defaultMinutes = config.GetValue<int>("Alerts:DefaultThrottleWindowMinutes", 60);
        _defaultThrottleWindow = TimeSpan.FromMinutes(defaultMinutes);

        // Load fraud type configurations
        _fraudTypeConfigs = LoadFraudTypeConfigs();

        _logger.LogInformation(
            "HybridAlertService initialized. Database persistence: {Enabled}, Default window: {Window} min",
            _enableDatabasePersistence,
            defaultMinutes);
    }

    /// <summary>
    /// Initialize service and warm up in-memory cache from database (if enabled)
    /// </summary>
    public async Task InitializeAsync()
    {
        if (_enableDatabasePersistence && _historyService != null)
        {
            _logger.LogInformation("Warming up alert cache from database...");

            try
            {
                var recentAlerts = await _historyService.GetRecentAlertsForWarmupAsync(_defaultThrottleWindow);
                var warmupCount = 0;

                foreach (var alert in recentAlerts)
                {
                    var key = BuildThrottleKey(alert.DeviceKey, alert.RiskLevel, alert.FraudType);
                    _throttleCache[key] = new ThrottleEntry
                    {
                        LastAlertTime = alert.SentAt,
                        SessionId = alert.SessionId,
                        FraudType = alert.FraudType,
                        RiskLevel = alert.RiskLevel,
                        DeviceKey = alert.DeviceKey,
                        UserId = alert.UserId
                    };
                    warmupCount++;
                }

                _logger.LogInformation("Alert cache warmed up with {Count} recent alerts", warmupCount);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to warm up cache from database, continuing with empty cache");
            }
        }
        else
        {
            _logger.LogInformation("Database persistence disabled, using in-memory only");
        }
    }

    /// <summary>
    /// Determines if an alert should be sent based on fraud-type-aware throttling
    /// </summary>
    public async Task<AlertDecision> ShouldSendAlertAsync(FraudAnalysisResult result)
    {
        var now = DateTime.UtcNow;
        var decision = new AlertDecision
        {
            ShouldSend = false,
            Reason = "",
            DecisionTime = now
        };

        // Detect all fraud types (main + pattern-based)
        var allFraudTypes = DetectAllFraudTypes(result);
        decision.AllDetectedFraudTypes = allFraudTypes;

        if (!allFraudTypes.Any())
        {
            decision.Reason = "No significant fraud types detected";
            return decision;
        }

        // Check each fraud type against throttle
        foreach (var fraudType in allFraudTypes)
        {
            var config = GetFraudTypeConfig(fraudType);

            if (!config.Enabled)
            {
                _logger.LogDebug("Fraud type {Type} is disabled in configuration", fraudType);
                continue;
            }

            var key = BuildThrottleKey(result.DeviceKey, result.RiskLevel, fraudType);
            var throttleWindow = config.ThrottleWindow;

            if (_throttleCache.TryGetValue(key, out var entry))
            {
                var timeSinceLastAlert = now - entry.LastAlertTime;

                if (timeSinceLastAlert < throttleWindow)
                {
                    // This fraud type was recently alerted - THROTTLE
                    decision.ThrottledFraudTypes.Add(fraudType);

                    _logger.LogDebug(
                        "⏸️ Throttling {FraudType} for device {Device}. Last alert: {Time} ago (window: {Window} min)",
                        fraudType,
                        result.DeviceKey,
                        timeSinceLastAlert.TotalMinutes.ToString("F1"),
                        throttleWindow.TotalMinutes);
                    continue;
                }
            }

            // This is a NEW fraud type (or throttle window expired) - ALERT!
            decision.FraudTypesToAlert.Add(fraudType);

            // Update in-memory cache
            _throttleCache[key] = new ThrottleEntry
            {
                LastAlertTime = now,
                SessionId = result.SessionId,
                FraudType = fraudType,
                RiskLevel = result.RiskLevel,
                DeviceKey = result.DeviceKey,
                UserId = result.UserId ?? ""
            };

            _logger.LogInformation(
                "🆕 NEW fraud type: {FraudType} for device {Device} (Risk: {Risk})",
                fraudType,
                result.DeviceKey,
                result.RiskLevel);
        }

        // Set decision
        if (decision.FraudTypesToAlert.Any())
        {
            decision.ShouldSend = true;
            decision.Reason = $"New fraud types detected: {string.Join(", ", decision.FraudTypesToAlert)}";

            // Optionally persist to database
            if (_enableDatabasePersistence && _historyService != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _historyService.RecordAlertAsync(result, decision.FraudTypesToAlert);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to persist alert to database");
                    }
                });
            }
        }
        else
        {
            decision.Reason = "All fraud types recently alerted (throttled)";
        }

        // Cleanup old entries periodically
        if (now.Second == 0) // Once per minute
        {
            CleanupOldEntries(now);
        }

        return decision;
    }

    /// <summary>
    /// Detects all fraud types from the analysis result (main + pattern-based)
    /// </summary>
    private List<string> DetectAllFraudTypes(FraudAnalysisResult result)
    {
        var fraudTypes = new List<string>();

        // Main fraud types (from flags)
        if (result.IsMultiAccounting)
            fraudTypes.Add("MultiAccounting");

        if (result.IsMultiDevicing)
            fraudTypes.Add("MultiDevicing");

        if (result.IsAccountTakeover)
            fraudTypes.Add("AccountTakeover");

        if (result.IsImpossibleTravel)
            fraudTypes.Add("ImpossibleTravel");

        // Pattern-based fraud types (from SuspiciousReasons)
        foreach (var reason in result.SuspiciousReasons)
        {
            // OTP Bruteforce
            if ((reason.Contains("OTP", StringComparison.OrdinalIgnoreCase) &&
                 reason.Contains("failure", StringComparison.OrdinalIgnoreCase)) ||
                (reason.Contains("OTP", StringComparison.OrdinalIgnoreCase) &&
                 reason.Contains("attempts", StringComparison.OrdinalIgnoreCase)))
            {
                if (!fraudTypes.Contains("OtpBruteforce"))
                    fraudTypes.Add("OtpBruteforce");
            }

            // Device Spoofing
            if (reason.Contains("Rooted", StringComparison.OrdinalIgnoreCase) ||
                reason.Contains("Emulator", StringComparison.OrdinalIgnoreCase) ||
                reason.Contains("Mock", StringComparison.OrdinalIgnoreCase))
            {
                if (!fraudTypes.Contains("DeviceSpoofing"))
                    fraudTypes.Add("DeviceSpoofing");
            }

            // VPN Usage
            if (reason.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                reason.Contains("proxy", StringComparison.OrdinalIgnoreCase))
            {
                if (!fraudTypes.Contains("VpnUsage"))
                    fraudTypes.Add("VpnUsage");
            }

            // Unusual Timing
            if (reason.Contains("night", StringComparison.OrdinalIgnoreCase) ||
                reason.Contains("2-5 AM", StringComparison.OrdinalIgnoreCase) ||
                reason.Contains("unusual hour", StringComparison.OrdinalIgnoreCase))
            {
                if (!fraudTypes.Contains("UnusualTiming"))
                    fraudTypes.Add("UnusualTiming");
            }
        }

        // If high risk but no specific type detected, add generic
        if (!fraudTypes.Any() && result.RiskLevel is "CRITICAL" or "HIGH")
        {
            fraudTypes.Add("GeneralSuspicious");
        }

        return fraudTypes;
    }

    /// <summary>
    /// Builds unique throttle key for device/user + risk level + fraud type
    /// </summary>
    private string BuildThrottleKey(string deviceKey, string riskLevel, string fraudType)
    {
        // For user-based fraud, we'd ideally use UserId, but DeviceKey works for all cases
        return $"{deviceKey}:{riskLevel}:{fraudType}";
    }

    /// <summary>
    /// Gets configuration for specific fraud type
    /// </summary>
    private FraudTypeConfig GetFraudTypeConfig(string fraudType)
    {
        if (_fraudTypeConfigs.TryGetValue(fraudType, out var config))
            return config;

        // Return default config if not found
        return new FraudTypeConfig
        {
            Enabled = true,
            ThrottleWindow = _defaultThrottleWindow,
            Priority = "MEDIUM"
        };
    }

    /// <summary>
    /// Loads fraud type configurations from appsettings.json
    /// </summary>
    private Dictionary<string, FraudTypeConfig> LoadFraudTypeConfigs()
    {
        var configs = new Dictionary<string, FraudTypeConfig>();
        var section = _config.GetSection("Alerts:FraudTypeSettings");

        foreach (var fraudType in new[]
        {
            "MultiAccounting", "MultiDevicing", "AccountTakeover", "ImpossibleTravel",
            "OtpBruteforce", "DeviceSpoofing", "VpnUsage", "UnusualTiming", "GeneralSuspicious"
        })
        {
            var typeSection = section.GetSection(fraudType);
            var enabled = typeSection.GetValue<bool>("Enabled", true);
            var minutes = typeSection.GetValue<int>("ThrottleWindowMinutes", (int)_defaultThrottleWindow.TotalMinutes);
            var priority = typeSection.GetValue<string>("Priority", "MEDIUM");

            configs[fraudType] = new FraudTypeConfig
            {
                Enabled = enabled,
                ThrottleWindow = TimeSpan.FromMinutes(minutes),
                Priority = priority ?? "MEDIUM"
            };
        }

        return configs;
    }

    /// <summary>
    /// Removes old throttle entries to prevent memory bloat
    /// </summary>
    private void CleanupOldEntries(DateTime now)
    {
        var cutoff = now - (_defaultThrottleWindow * 2); // Keep 2x throttle window
        var keysToRemove = _throttleCache
            .Where(kvp => kvp.Value.LastAlertTime < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            _throttleCache.TryRemove(key, out _);
        }

        if (keysToRemove.Any())
        {
            _logger.LogDebug("Cleaned up {Count} old throttle entries", keysToRemove.Count);
        }
    }

    /// <summary>
    /// Manually clear throttle for a device (useful for testing/debugging)
    /// </summary>
    public void ClearThrottle(string deviceKey, string? fraudType = null)
    {
        var keysToRemove = _throttleCache.Keys
            .Where(k => k.StartsWith(deviceKey) &&
                       (fraudType == null || k.Contains(fraudType)))
            .ToList();

        foreach (var key in keysToRemove)
        {
            _throttleCache.TryRemove(key, out _);
            _logger.LogInformation("Cleared throttle for {Key}", key);
        }
    }

    /// <summary>
    /// Get current throttle state (for monitoring/debugging)
    /// </summary>
    public Dictionary<string, ThrottleEntry> GetActiveThrottles()
    {
        return new Dictionary<string, ThrottleEntry>(_throttleCache);
    }

    /// <summary>
    /// Get statistics about current throttle state
    /// </summary>
    public ThrottleStatistics GetStatistics()
    {
        var now = DateTime.UtcNow;
        var entries = _throttleCache.Values.ToList();

        return new ThrottleStatistics
        {
            TotalEntries = entries.Count,
            ActiveEntries = entries.Count(e => now - e.LastAlertTime < _defaultThrottleWindow),
            OldestEntry = entries.Any() ? entries.Min(e => e.LastAlertTime) : (DateTime?)null,
            NewestEntry = entries.Any() ? entries.Max(e => e.LastAlertTime) : (DateTime?)null,
            EntriesByFraudType = entries.GroupBy(e => e.FraudType)
                .ToDictionary(g => g.Key, g => g.Count())
        };
    }
}

/// <summary>
/// In-memory throttle entry
/// </summary>
public class ThrottleEntry
{
    public DateTime LastAlertTime { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public string FraudType { get; set; } = string.Empty;
    public string RiskLevel { get; set; } = string.Empty;
    public string DeviceKey { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
}

/// <summary>
/// Configuration for a specific fraud type
/// </summary>
public class FraudTypeConfig
{
    public bool Enabled { get; set; }
    public TimeSpan ThrottleWindow { get; set; }
    public string Priority { get; set; } = "MEDIUM";
}

/// <summary>
/// Statistics about current throttle state
/// </summary>
public class ThrottleStatistics
{
    public int TotalEntries { get; set; }
    public int ActiveEntries { get; set; }
    public DateTime? OldestEntry { get; set; }
    public DateTime? NewestEntry { get; set; }
    public Dictionary<string, int> EntriesByFraudType { get; set; } = new();
}

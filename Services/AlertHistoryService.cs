using ClickHouse.Client.ADO;
using Dapper;
using FraudDetection.ML.Models;

namespace FraudDetection.ML.Services;

/// <summary>
/// Manages alert history to prevent duplicate alerts and implement fraud-type-aware throttling.
/// Only sends alerts when NEW fraud types are detected for a device/user.
/// </summary>
public class AlertHistoryService
{
    private readonly string _connectionString;
    private readonly ILogger<AlertHistoryService> _logger;
    private readonly TimeSpan _throttleWindow;

    public AlertHistoryService(
        IConfiguration config,
        ILogger<AlertHistoryService> logger)
    {
        _connectionString = config.GetConnectionString("ClickHouse")
            ?? throw new ArgumentNullException("ClickHouse connection string not found");
        _logger = logger;

        // Default throttle window: 24 hours
        var hours = config.GetValue<int>("Alerts:ThrottleWindowHours", 24);
        _throttleWindow = TimeSpan.FromHours(hours);
    }

    /// <summary>
    /// Ensures AlertHistory table exists in ClickHouse
    /// </summary>
    public async Task InitializeAsync()
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var createTableQuery = @"
            CREATE TABLE IF NOT EXISTS AlertHistory
            (
                AlertId String,
                SessionId String,
                DeviceKey String,
                GlobalDeviceId String,
                UserId String,
                PhoneNumber String,
                RiskLevel String,
                FraudTypes Array(String),
                SentAt DateTime,
                ThrottleKey String
            )
            ENGINE = MergeTree()
            ORDER BY (SentAt, DeviceKey, UserId)
            TTL SentAt + INTERVAL 30 DAY";

        await connection.ExecuteAsync(createTableQuery);
        _logger.LogInformation("AlertHistory table initialized");
    }

    /// <summary>
    /// Checks if an alert should be sent based on fraud-type-aware throttling.
    /// Returns list of NEW fraud types that should trigger an alert.
    /// </summary>
    /// <returns>List of new fraud types to alert on (empty if all are throttled)</returns>
    public async Task<List<string>> GetNewFraudTypesAsync(FraudAnalysisResult result)
    {
        var detectedFraudTypes = GetDetectedFraudTypes(result);

        if (!detectedFraudTypes.Any())
        {
            _logger.LogDebug("No fraud types detected for session {SessionId}", result.SessionId);
            return new List<string>();
        }

        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var cutoffTime = DateTime.UtcNow - _throttleWindow;

        // Check each fraud type to see if it's been alerted on recently
        var newFraudTypes = new List<string>();

        foreach (var fraudType in detectedFraudTypes)
        {
            var throttleKey = BuildThrottleKey(result, fraudType);

            var query = @"
                SELECT COUNT(*) as AlertCount
                FROM AlertHistory
                WHERE ThrottleKey = @ThrottleKey
                  AND SentAt >= @CutoffTime
                LIMIT 1";

            var count = await connection.ExecuteScalarAsync<int>(
                query,
                new { ThrottleKey = throttleKey, CutoffTime = cutoffTime });

            if (count == 0)
            {
                // This fraud type has NOT been alerted on recently - it's NEW!
                newFraudTypes.Add(fraudType);
                _logger.LogInformation(
                    "🆕 NEW fraud type detected: {FraudType} for {Entity} (Throttle Key: {Key})",
                    fraudType,
                    result.UserId ?? result.DeviceKey,
                    throttleKey);
            }
            else
            {
                // This fraud type was already alerted on - THROTTLE it
                _logger.LogDebug(
                    "⏸️ Throttling {FraudType} for {Entity} (already alerted within {Hours}h)",
                    fraudType,
                    result.UserId ?? result.DeviceKey,
                    _throttleWindow.TotalHours);
            }
        }

        return newFraudTypes;
    }

    /// <summary>
    /// Records that an alert was sent for specific fraud types
    /// </summary>
    public async Task RecordAlertAsync(FraudAnalysisResult result, List<string> fraudTypes)
    {
        if (!fraudTypes.Any()) return;

        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var alertId = Guid.NewGuid().ToString();
        var sentAt = DateTime.UtcNow;

        // Record an entry for each fraud type separately
        foreach (var fraudType in fraudTypes)
        {
            var throttleKey = BuildThrottleKey(result, fraudType);

            var insertQuery = @"
                INSERT INTO AlertHistory VALUES
                (@AlertId, @SessionId, @DeviceKey, @GlobalDeviceId, @UserId, @PhoneNumber,
                 @RiskLevel, @FraudTypes, @SentAt, @ThrottleKey)";

            await connection.ExecuteAsync(insertQuery, new
            {
                AlertId = $"{alertId}-{fraudType}",
                result.SessionId,
                result.DeviceKey,
                GlobalDeviceId = result.GlobalDeviceId.ToString(),
                result.UserId,
                result.PhoneNumber,
                result.RiskLevel,
                FraudTypes = new[] { fraudType },
                SentAt = sentAt,
                ThrottleKey = throttleKey
            });

            _logger.LogInformation(
                "✅ Alert recorded: {FraudType} for {Entity} at {Time}",
                fraudType,
                result.UserId ?? result.DeviceKey,
                sentAt);
        }
    }

    /// <summary>
    /// Builds a unique throttle key for a specific fraud type on a device/user
    /// Format: "device:{DeviceKey}:CRITICAL:MultiAccounting" or "user:{UserId}:HIGH:ImpossibleTravel"
    /// </summary>
    private string BuildThrottleKey(FraudAnalysisResult result, string fraudType)
    {
        // For user-based fraud (multi-devicing, impossible travel), use UserId
        if (fraudType == "ImpossibleTravel" || fraudType == "MultiDevicing")
        {
            var userId = result.UserId ?? "unknown";
            return $"user:{userId}:{result.RiskLevel}:{fraudType}";
        }

        // For device-based fraud (multi-accounting, account takeover), use DeviceKey
        return $"device:{result.DeviceKey}:{result.RiskLevel}:{fraudType}";
    }

    /// <summary>
    /// Extracts detected fraud types from analysis result
    /// </summary>
    private List<string> GetDetectedFraudTypes(FraudAnalysisResult result)
    {
        var fraudTypes = new List<string>();

        if (result.IsMultiAccounting) fraudTypes.Add("MultiAccounting");
        if (result.IsMultiDevicing) fraudTypes.Add("MultiDevicing");
        if (result.IsAccountTakeover) fraudTypes.Add("AccountTakeover");
        if (result.IsImpossibleTravel) fraudTypes.Add("ImpossibleTravel");

        return fraudTypes;
    }

    /// <summary>
    /// Gets alert statistics for a time period
    /// </summary>
    public async Task<AlertStatistics> GetAlertStatisticsAsync(DateTime fromDate)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            SELECT
                COUNT(*) as TotalAlerts,
                uniqExact(DeviceKey) as UniqueDevices,
                uniqExact(UserId) as UniqueUsers,
                countIf(RiskLevel = 'CRITICAL') as CriticalAlerts,
                countIf(RiskLevel = 'HIGH') as HighAlerts,
                countIf(arrayExists(x -> x = 'MultiAccounting', FraudTypes)) as MultiAccountingAlerts,
                countIf(arrayExists(x -> x = 'MultiDevicing', FraudTypes)) as MultiDevicingAlerts,
                countIf(arrayExists(x -> x = 'AccountTakeover', FraudTypes)) as AccountTakeoverAlerts,
                countIf(arrayExists(x -> x = 'ImpossibleTravel', FraudTypes)) as ImpossibleTravelAlerts
            FROM AlertHistory
            WHERE SentAt >= @FromDate";

        var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
            query,
            new { FromDate = fromDate });

        return new AlertStatistics
        {
            TotalAlerts = Convert.ToInt32(result?.TotalAlerts ?? 0),
            UniqueDevices = Convert.ToInt32(result?.UniqueDevices ?? 0),
            UniqueUsers = Convert.ToInt32(result?.UniqueUsers ?? 0),
            CriticalAlerts = Convert.ToInt32(result?.CriticalAlerts ?? 0),
            HighAlerts = Convert.ToInt32(result?.HighAlerts ?? 0),
            MultiAccountingAlerts = Convert.ToInt32(result?.MultiAccountingAlerts ?? 0),
            MultiDevicingAlerts = Convert.ToInt32(result?.MultiDevicingAlerts ?? 0),
            AccountTakeoverAlerts = Convert.ToInt32(result?.AccountTakeoverAlerts ?? 0),
            ImpossibleTravelAlerts = Convert.ToInt32(result?.ImpossibleTravelAlerts ?? 0)
        };
    }
}

/// <summary>
/// Alert statistics model
/// </summary>
public class AlertStatistics
{
    public int TotalAlerts { get; set; }
    public int UniqueDevices { get; set; }
    public int UniqueUsers { get; set; }
    public int CriticalAlerts { get; set; }
    public int HighAlerts { get; set; }
    public int MultiAccountingAlerts { get; set; }
    public int MultiDevicingAlerts { get; set; }
    public int AccountTakeoverAlerts { get; set; }
    public int ImpossibleTravelAlerts { get; set; }
}

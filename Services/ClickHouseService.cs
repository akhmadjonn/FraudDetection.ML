using ClickHouse.Client.ADO;
using Dapper;
using FraudDetection.ML.Models;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FraudDetection.ML.Services;

public class ClickHouseService
{
    private readonly string _connectionString;
    private readonly ILogger<ClickHouseService> _logger;

    public ClickHouseService(IConfiguration config, ILogger<ClickHouseService> logger)
    {
        _connectionString = config.GetConnectionString("ClickHouse")
            ?? throw new ArgumentNullException("ClickHouse connection string not found");
        _logger = logger;
    }

    // ==================== SESSION QUERIES ====================

    public async Task<List<SessionRecord>> GetRecentSessionsAsync(
        DateTime fromDate,
        int limit = 10000)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            SELECT 
                Id, SessionId, GlobalId, GlobalDeviceId,
                DeviceContext, Type, CreatedAt, ExpireAt,
                DeviceKey, AppSetId, MetaData, ProfileId
            FROM Sessions
            WHERE CreatedAt >= @FromDate
            ORDER BY CreatedAt DESC
            LIMIT @Limit";

        var sessions = await connection.QueryAsync<SessionRecord>(
            query,
            new { FromDate = fromDate, Limit = limit });

        return sessions.ToList();
    }

    // ==================== EVENT QUERIES ====================

    public async Task<List<EventRecord>> GetSessionEventsAsync(string sessionId)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            SELECT 
                Id, SessionId, EventName, EventType,
                EventTime, EventParams, CreatedAt
            FROM Events
            WHERE SessionId = @SessionId
            ORDER BY EventTime";

        var events = await connection.QueryAsync<EventRecord>(
            query,
            new { SessionId = sessionId });

        return events.ToList();
    }

    // ==================== DEVICE HISTORY ====================

    public async Task<DeviceHistory> GetDeviceHistoryAsync(
        Guid globalDeviceId,
        DateTime fromDate)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            SELECT 
                COUNT(DISTINCT SessionId) as TotalSessions,
                COUNT(DISTINCT JSONExtractString(DeviceContext, 'Network', 'XClientIp')) as UniqueIpCount,
                COUNT(DISTINCT JSONExtractString(DeviceContext, 'Network', 'OperatorName')) as DifferentCarrierCount
            FROM Sessions
            WHERE GlobalDeviceId = @GlobalDeviceId
              AND CreatedAt >= @FromDate";

        var history = await connection.QueryFirstOrDefaultAsync<DeviceHistory>(
            query,
            new { GlobalDeviceId = globalDeviceId, FromDate = fromDate });

        return history ?? new DeviceHistory();
    }

    // ==================== MULTI-ACCOUNTING QUERIES ====================

    public async Task<MultiAccountingHistory> GetMultiAccountingHistoryAsync(
    Guid globalDeviceId)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var now = DateTime.UtcNow;

        // Get unique users and phone numbers for different time windows
        var query = @"
        WITH parsed_metadata AS (
            SELECT 
                SessionId,
                CreatedAt,
                JSONExtractString(MetaData, 'userId') as UserId,
                JSONExtractString(MetaData, 'phoneNumber') as PhoneNumber,
                DeviceContext
            FROM Sessions
            WHERE GlobalDeviceId = @GlobalDeviceId
              AND MetaData != ''
              AND MetaData != 'null'
              AND CreatedAt >= @From30Days
        )
        SELECT 
            uniqExact(UserId) as TotalUniqueUsers,
            uniqExactIf(UserId, CreatedAt >= @From24Hours) as UniqueUserIds_24h,
            uniqExactIf(UserId, CreatedAt >= @From7Days) as UniqueUserIds_7d,
            uniqExact(UserId) as UniqueUserIds_30d,
            uniqExactIf(PhoneNumber, CreatedAt >= @From7Days) as UniquePhoneNumbers_7d,
            countIf(CreatedAt >= @From24Hours) as NewUsers_24h,
            countIf(CreatedAt >= @From7Days) as NewUsers_7d
        FROM parsed_metadata
        WHERE UserId != ''";

        var result = await connection.QueryFirstOrDefaultAsync<dynamic>(query, new
        {
            GlobalDeviceId = globalDeviceId,
            From24Hours = now.AddHours(-24),
            From7Days = now.AddDays(-7),
            From30Days = now.AddDays(-30)
        });

        // Get user behavior patterns
        var behaviorQuery = @"
        WITH parsed_metadata AS (
            SELECT 
                s.SessionId,
                JSONExtractString(s.MetaData, 'userId') as UserId,
                s.CreatedAt
            FROM Sessions s
            WHERE s.GlobalDeviceId = @GlobalDeviceId
              AND s.MetaData != ''
              AND s.MetaData != 'null'
              AND s.CreatedAt >= @From7Days
        ),
        user_events AS (
            SELECT 
                pm.UserId,
                e.EventName
            FROM parsed_metadata pm
            INNER JOIN Events e ON e.SessionId = pm.SessionId
            WHERE pm.UserId != ''
        )
        SELECT 
            UserId,
            countIf(EventName = 'add_card_otp_success_entered') as CardAdditions,
            countIf(EventName = 'p2p_otp_success') as P2PTransfers,
            countIf(EventName = 'payment_confirm') as Payments,
            countIf(EventName IN ('add_card_otp_unsuccess_entered', 'otp_page_error')) as OtpFailures
        FROM user_events
        GROUP BY UserId";

        var behaviors = await connection.QueryAsync<UserBehaviorPattern>(
            behaviorQuery,
            new { GlobalDeviceId = globalDeviceId, From7Days = now.AddDays(-7) });

        // Calculate user switches - Using simplified approach
        var switchQuery = @"
        SELECT COUNT(DISTINCT JSONExtractString(MetaData, 'userId')) - 1 as Switches
        FROM Sessions
        WHERE GlobalDeviceId = @GlobalDeviceId
          AND MetaData != ''
          AND MetaData != 'null'
          AND JSONExtractString(MetaData, 'userId') != ''
          AND CreatedAt >= @From7Days
        HAVING COUNT(DISTINCT JSONExtractString(MetaData, 'userId')) > 1";

        var switches = await connection.QueryFirstOrDefaultAsync<int?>(
            switchQuery,
            new { GlobalDeviceId = globalDeviceId, From7Days = now.AddDays(-7) }) ?? 0;

        return new MultiAccountingHistory
        {
            UniqueUserIds_24h = (int)(result?.UniqueUserIds_24h ?? 0),
            UniqueUserIds_7d = (int)(result?.UniqueUserIds_7d ?? 0),
            UniqueUserIds_30d = (int)(result?.UniqueUserIds_30d ?? 0),
            UniquePhoneNumbers_7d = (int)(result?.UniquePhoneNumbers_7d ?? 0),
            NewUsers_24h = (int)(result?.NewUsers_24h ?? 0),
            NewUsers_7d = (int)(result?.NewUsers_7d ?? 0),
            UserSwitches = switches,
            UserBehaviors = behaviors.ToList()
        };
    }

    // ==================== MULTI-DEVICING QUERIES ====================

    public async Task<MultiDevicingHistory> GetMultiDevicingHistoryAsync(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return new MultiDevicingHistory();

        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var now = DateTime.UtcNow;

        // Get device counts and changes
        var query = @"
            WITH user_sessions AS (
                SELECT 
                    SessionId,
                    GlobalDeviceId,
                    DeviceKey,
                    CreatedAt,
                    JSONExtractString(DeviceContext, 'Network', 'XClientIp') as IpAddress,
                    JSONExtractString(DeviceContext, 'Network', 'OperatorName') as Carrier,
                    JSONExtractString(DeviceContext, 'Application', 'InstallTimestamp') as InstallTime
                FROM Sessions
                WHERE JSONExtractString(MetaData, 'userId') = @UserId
                  AND MetaData != ''
                  AND CreatedAt >= @From30Days
            )
            SELECT 
                uniqExactIf(GlobalDeviceId, CreatedAt >= @From24Hours) as UniqueDevices_24h,
                uniqExactIf(GlobalDeviceId, CreatedAt >= @From7Days) as UniqueDevices_7d,
                uniqExact(GlobalDeviceId) as UniqueDevices_30d,
                uniqExact(GlobalDeviceId) as TotalDevicesEverUsed,
                uniqExactIf(IpAddress, CreatedAt >= @From24Hours) as IpChanges_24h,
                uniqExactIf(IpAddress, CreatedAt >= @From7Days) as IpChanges_7d,
                uniqExactIf(Carrier, CreatedAt >= @From7Days) as CarrierChanges_7d
            FROM user_sessions";

        var result = await connection.QueryFirstOrDefaultAsync<dynamic>(query, new
        {
            UserId = userId,
            From24Hours = now.AddHours(-24),
            From7Days = now.AddDays(-7),
            From30Days = now.AddDays(-30)
        });

        // Get recent device logins for geographic analysis
        var deviceQuery = @"
            SELECT 
                GlobalDeviceId as DeviceKey,
                GlobalDeviceId,
                CreatedAt as LoginTime,
                JSONExtractString(DeviceContext, 'Network', 'XClientIp') as IpAddress,
                JSONExtractString(DeviceContext, 'Network', 'OperatorName') as Carrier,
                concat(
                    JSONExtractString(DeviceContext, 'Network', 'Mcc'),
                    '-',
                    JSONExtractString(DeviceContext, 'Network', 'Mnc')
                ) as Location
            FROM Sessions
            WHERE JSONExtractString(MetaData, 'userId') = @UserId
              AND MetaData != ''
              AND CreatedAt >= @From7Days
            ORDER BY CreatedAt DESC
            LIMIT 20";

        var devices = await connection.QueryAsync<DeviceLoginInfo>(
            deviceQuery,
            new { UserId = userId, From7Days = now.AddDays(-7) });

        var deviceList = devices.ToList();

        // Detect impossible travel (devices from different locations in short time)
        var geographicJumps = DetectGeographicJumps(deviceList);

        return new MultiDevicingHistory
        {
            UniqueDevices_24h = result?.UniqueDevices_24h ?? 0,
            UniqueDevices_7d = result?.UniqueDevices_7d ?? 0,
            UniqueDevices_30d = result?.UniqueDevices_30d ?? 0,
            TotalDevicesEverUsed = result?.TotalDevicesEverUsed ?? 0,
            IpChanges_24h = result?.IpChanges_24h ?? 0,
            IpChanges_7d = result?.IpChanges_7d ?? 0,
            CarrierChanges_7d = result?.CarrierChanges_7d ?? 0,
            GeographicJumps_24h = geographicJumps,
            HasImpossibleTravel = geographicJumps > 0,
            RecentDevices = deviceList
        };
    }

    private int DetectGeographicJumps(List<DeviceLoginInfo> devices)
    {
        if (devices.Count < 2) return 0;

        int jumps = 0;
        var sortedDevices = devices.OrderBy(d => d.LoginTime).ToList();

        for (int i = 1; i < sortedDevices.Count; i++)
        {
            var prev = sortedDevices[i - 1];
            var current = sortedDevices[i];
            var timeDiff = (current.LoginTime - prev.LoginTime).TotalHours;

            // If different carriers or locations AND less than 2 hours apart
            if (timeDiff < 2 &&
                (prev.Carrier != current.Carrier || prev.Location != current.Location))
            {
                jumps++;
            }
        }

        return jumps;
    }

    // ==================== METADATA PARSING ====================

    public MetaDataInfo ParseMetaData(string metaData)
    {
        if (string.IsNullOrWhiteSpace(metaData) || metaData == "null")
            return new MetaDataInfo();

        try
        {
            // Try JSON parsing first
            var json = JsonSerializer.Deserialize<MetaDataInfo>(metaData);
            if (json != null) return json;
        }
        catch
        {
            // If JSON fails, try regex parsing for format: {phoneNumber: X, userId: Y, deviceId: Z}
            try
            {
                var phoneMatch = Regex.Match(metaData, @"phoneNumber:\s*([^,}]+)");
                var userMatch = Regex.Match(metaData, @"userId:\s*([^,}]+)");
                var deviceMatch = Regex.Match(metaData, @"deviceId:\s*([^,}]+)");

                return new MetaDataInfo
                {
                    PhoneNumber = phoneMatch.Success ? phoneMatch.Groups[1].Value.Trim() : string.Empty,
                    UserId = userMatch.Success ? userMatch.Groups[1].Value.Trim() : string.Empty,
                    DeviceId = deviceMatch.Success ? deviceMatch.Groups[1].Value.Trim() : string.Empty
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse MetaData: {MetaData}", metaData);
            }
        }

        return new MetaDataInfo();
    }

    // ==================== SAVE RESULTS ====================

    public async Task SaveAnalysisResultAsync(FraudAnalysisResult result)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        // Create table if not exists
        var createTableQuery = @"
            CREATE TABLE IF NOT EXISTS FraudAnalysisResults
            (
                SessionId String,
                ProfileId String,
                DeviceKey String,
                GlobalDeviceId String,
                UserId String,
                PhoneNumber String,
                AnalyzedAt DateTime,
                AnomalyScore Float32,
                IsAnomaly UInt8,
                ClusterId UInt32,
                RiskLevel String,
                IsMultiAccounting UInt8,
                IsMultiDevicing UInt8,
                IsAccountTakeover UInt8,
                IsImpossibleTravel UInt8,
                SuspiciousReasons Array(String),
                Features String
            )
            ENGINE = MergeTree()
            ORDER BY (AnalyzedAt, SessionId)";

        await connection.ExecuteAsync(createTableQuery);

        // Insert result
        var insertQuery = @"
            INSERT INTO FraudAnalysisResults VALUES
            (@SessionId, @ProfileId, @DeviceKey, @GlobalDeviceId, @UserId, @PhoneNumber,
             @AnalyzedAt, @AnomalyScore, @IsAnomaly, @ClusterId, @RiskLevel,
             @IsMultiAccounting, @IsMultiDevicing, @IsAccountTakeover, @IsImpossibleTravel,
             @SuspiciousReasons, @Features)";

        await connection.ExecuteAsync(insertQuery, new
        {
            result.SessionId,
            result.ProfileId,
            result.DeviceKey,
            result.GlobalDeviceId,
            result.UserId,
            result.PhoneNumber,
            result.AnalyzedAt,
            result.AnomalyScore,
            IsAnomaly = result.IsAnomaly ? 1 : 0,
            result.ClusterId,
            result.RiskLevel,
            IsMultiAccounting = result.IsMultiAccounting ? 1 : 0,
            IsMultiDevicing = result.IsMultiDevicing ? 1 : 0,
            IsAccountTakeover = result.IsAccountTakeover ? 1 : 0,
            IsImpossibleTravel = result.IsImpossibleTravel ? 1 : 0,
            SuspiciousReasons = result.SuspiciousReasons.ToArray(),
            Features = JsonSerializer.Serialize(result.Features)
        });
    }

    // ==================== REPORTING QUERIES ====================

    public async Task<List<FraudAnalysisResult>> GetAnalysisResultsAsync(
        DateTime fromDate,
        DateTime toDate)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            SELECT 
                SessionId, ProfileId, DeviceKey, GlobalDeviceId, UserId, PhoneNumber,
                AnalyzedAt, AnomalyScore, IsAnomaly, ClusterId, RiskLevel,
                IsMultiAccounting, IsMultiDevicing, IsAccountTakeover, IsImpossibleTravel,
                SuspiciousReasons, Features
            FROM FraudAnalysisResults
            WHERE AnalyzedAt >= @FromDate AND AnalyzedAt < @ToDate
            ORDER BY AnomalyScore DESC";

        var results = await connection.QueryAsync<dynamic>(query, new { FromDate = fromDate, ToDate = toDate });

        return results.Select(r => new FraudAnalysisResult
        {
            SessionId = r.SessionId,
            ProfileId = r.ProfileId,
            DeviceKey = r.DeviceKey,
            GlobalDeviceId = r.GlobalDeviceId,
            UserId = r.UserId,
            PhoneNumber = r.PhoneNumber,
            AnalyzedAt = r.AnalyzedAt,
            AnomalyScore = r.AnomalyScore,
            IsAnomaly = r.IsAnomaly == 1,
            ClusterId = r.ClusterId,
            RiskLevel = r.RiskLevel,
            IsMultiAccounting = r.IsMultiAccounting == 1,
            IsMultiDevicing = r.IsMultiDevicing == 1,
            IsAccountTakeover = r.IsAccountTakeover == 1,
            IsImpossibleTravel = r.IsImpossibleTravel == 1,
            SuspiciousReasons = ((string[])r.SuspiciousReasons).ToList(),
            Features = JsonSerializer.Deserialize<FraudFeatures>(r.Features) ?? new FraudFeatures()
        }).ToList();
    }

    public async Task<List<MultiAccountingCase>> GetTopMultiAccountingDevicesAsync(
        DateTime fromDate,
        int limit = 10)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            WITH device_users AS (
                SELECT 
                    GlobalDeviceId,
                    DeviceKey,
                    groupArray(DISTINCT UserId) as UserIds,
                    groupArray(DISTINCT PhoneNumber) as PhoneNumbers,
                    min(AnalyzedAt) as FirstSeen,
                    max(AnalyzedAt) as LastSeen,
                    avg(AnomalyScore) as AvgScore
                FROM FraudAnalysisResults
                WHERE AnalyzedAt >= @FromDate
                  AND IsMultiAccounting = 1
                  AND UserId != ''
                GROUP BY GlobalDeviceId, DeviceKey
            )
            SELECT 
                GlobalDeviceId,
                DeviceKey,
                length(UserIds) as UniqueUserCount,
                UserIds,
                PhoneNumbers,
                FirstSeen,
                LastSeen,
                AvgScore as RiskScore
            FROM device_users
            ORDER BY UniqueUserCount DESC, AvgScore DESC
            LIMIT @Limit";

        var cases = await connection.QueryAsync<MultiAccountingCase>(
            query,
            new { FromDate = fromDate, Limit = limit });

        return cases.ToList();
    }

    public async Task<List<MultiDevicingCase>> GetTopMultiDevicingUsersAsync(
        DateTime fromDate,
        int limit = 10)
    {
        using var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync();

        var query = @"
            WITH user_devices AS (
                SELECT 
                    UserId,
                    any(PhoneNumber) as PhoneNumber,
                    groupArray(DISTINCT DeviceKey) as DeviceKeys,
                    min(AnalyzedAt) as FirstSeen,
                    max(AnalyzedAt) as LastSeen,
                    avg(AnomalyScore) as AvgScore,
                    max(IsImpossibleTravel) as HasImpossibleTravel,
                    sum(IsImpossibleTravel) as GeographicJumps
                FROM FraudAnalysisResults
                WHERE AnalyzedAt >= @FromDate
                  AND IsMultiDevicing = 1
                  AND UserId != ''
                GROUP BY UserId
            )
            SELECT 
                UserId,
                PhoneNumber,
                length(DeviceKeys) as UniqueDeviceCount,
                DeviceKeys,
                HasImpossibleTravel,
                GeographicJumps,
                FirstSeen,
                LastSeen,
                AvgScore as RiskScore
            FROM user_devices
            ORDER BY UniqueDeviceCount DESC, AvgScore DESC
            LIMIT @Limit";

        var cases = await connection.QueryAsync<MultiDevicingCase>(
            query,
            new { FromDate = fromDate, Limit = limit });

        return cases.ToList();
    }
}
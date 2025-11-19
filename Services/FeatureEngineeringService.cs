using FraudDetection.ML.Models;
using System.Text.Json;

namespace FraudDetection.ML.Services;

public class FeatureEngineeringService
{
    private readonly ClickHouseService _clickHouse;
    private readonly ILogger<FeatureEngineeringService> _logger;

    public FeatureEngineeringService(
        ClickHouseService clickHouse,
        ILogger<FeatureEngineeringService> logger)
    {
        _clickHouse = clickHouse;
        _logger = logger;
    }

    public async Task<FraudFeatures?> ExtractFeaturesAsync(SessionRecord session)
    {
        try
        {
            // Parse DeviceContext JSON
            var deviceContext = JsonSerializer.Deserialize<DeviceContext>(session.DeviceContext);
            if (deviceContext == null)
            {
                _logger.LogWarning("Failed to parse DeviceContext for session {SessionId}", session.SessionId);
                return null;
            }

            // Parse MetaData
            var metaData = _clickHouse.ParseMetaData(session.MetaData);

            // Get session events
            var events = await _clickHouse.GetSessionEventsAsync(session.SessionId);

            // Get device history
            var deviceHistory = await _clickHouse.GetDeviceHistoryAsync(
                session.GlobalDeviceId,
                DateTime.UtcNow.AddDays(-30));

            // Get multi-accounting history
            var multiAccountingHistory = await _clickHouse.GetMultiAccountingHistoryAsync(
                session.GlobalDeviceId);

            // Get multi-devicing history (only if we have userId)
            var multiDevicingHistory = new MultiDevicingHistory();
            if (metaData.IsValid && !string.IsNullOrWhiteSpace(metaData.UserId))
            {
                multiDevicingHistory = await _clickHouse.GetMultiDevicingHistoryAsync(
                    metaData.UserId);
            }

            // Build features
            var features = new FraudFeatures
            {
                // Identifiers
                SessionId = session.SessionId,
                ProfileId = session.ProfileId,
                DeviceKey = session.DeviceKey,
                GlobalDeviceId = session.GlobalDeviceId,
                UserId = metaData.UserId,
                PhoneNumber = metaData.PhoneNumber,

                // Session features
                SessionDuration = CalculateSessionDuration(session),
                EventCount = events.Count,
                AverageTimeBetweenEvents = CalculateAvgTimeBetween(events),
                SessionStartHour = session.CreatedAt.Hour,
                DayOfWeek = (float)session.CreatedAt.DayOfWeek,
                SessionNumber = deviceHistory.TotalSessions,

                // Device features
                DeviceAgeInDays = CalculateDeviceAge(deviceContext),
                InstallToSessionMinutes = CalculateInstallToSession(deviceContext, session.CreatedAt),
                BatteryLevel = deviceContext.Device.BatteryLevel,
                RamFreeRatio = SafeDivide(deviceContext.Device.RamFree, deviceContext.Device.RamTotal),
                StorageFreeRatio = SafeDivide(deviceContext.Device.StorageFree, deviceContext.Device.StorageTotal),

                // Security features
                IsEmulator = deviceContext.Security.EmulatorStatus ? 1f : 0f,
                IsRooted = deviceContext.Security.RootStatus ? 1f : 0f,
                IsVpn = deviceContext.Network.VpnStatus ? 1f : 0f,
                IsCloned = deviceContext.Security.CloneStatus ? 1f : 0f,
                IsRoaming = deviceContext.Network.RoamingStatus ? 1f : 0f,

                // Behavioral features
                OtpFailureCount = CountOtpFailures(events),
                OtpSuccessCount = CountOtpSuccesses(events),
                OtpSuccessRate = CalculateOtpSuccessRate(events),
                CardAdditionCount = CountCardAdditions(events),
                P2PTransferCount = CountP2PTransfers(events),
                PaymentCount = CountPayments(events),
                TransferToPaymentRatio = CalculateTransferToPaymentRatio(events),

                // Historical features
                TotalSessionsForDevice = deviceHistory.TotalSessions,
                UniqueIpCount = deviceHistory.UniqueIpCount,
                DifferentCarrierCount = deviceHistory.DifferentCarrierCount,
                ConnectionIsMobile = deviceContext.Network.ConnectionType?.ToLower() == "mobile" ? 1f : 0f,

                // Multi-Accounting features
                UniqueUserIdsOnDevice_24h = multiAccountingHistory.UniqueUserIds_24h,
                UniqueUserIdsOnDevice_7d = multiAccountingHistory.UniqueUserIds_7d,
                UniqueUserIdsOnDevice_30d = multiAccountingHistory.UniqueUserIds_30d,
                UniquePhoneNumbersOnDevice_7d = multiAccountingHistory.UniquePhoneNumbers_7d,
                UserSwitchesPerDay = CalculateSwitchesPerDay(multiAccountingHistory.UserSwitches, 7),
                NewUserCreationsOnDevice_24h = multiAccountingHistory.NewUsers_24h,
                NewUserCreationsOnDevice_7d = multiAccountingHistory.NewUsers_7d,
                AccountSwitchingVelocity = multiAccountingHistory.AvgMinutesBetweenSwitches,
                SameActionPatternScore = CalculateSameActionScore(multiAccountingHistory.UserBehaviors),

                // Multi-Devicing features
                DevicesPerUser_24h = multiDevicingHistory.UniqueDevices_24h,
                DevicesPerUser_7d = multiDevicingHistory.UniqueDevices_7d,
                DevicesPerUser_30d = multiDevicingHistory.UniqueDevices_30d,
                NewDeviceLoginsForUser_7d = multiDevicingHistory.NewDeviceLogins_7d,
                DeviceSwitchesPerDayForUser = CalculateSwitchesPerDay(multiDevicingHistory.DeviceSwitches, 7),
                AlwaysNewDeviceFlag = IsAlwaysNewDevice(multiDevicingHistory),
                GeographicJumpCount_24h = multiDevicingHistory.GeographicJumps_24h,
                IpChangesForUser_24h = multiDevicingHistory.IpChanges_24h,
                IpChangesForUser_7d = multiDevicingHistory.IpChanges_7d,
                CarrierChangesForUser_7d = multiDevicingHistory.CarrierChanges_7d,
                SuspiciousVelocityFlag = multiDevicingHistory.HasImpossibleTravel ? 1f : 0f
            };

            return features;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting features for session {SessionId}", session.SessionId);
            return null;
        }
    }

    // ==================== CALCULATION HELPERS ====================

    private float CalculateSessionDuration(SessionRecord session)
    {
        if (session.ExpireAt.HasValue)
            return (float)(session.ExpireAt.Value - session.CreatedAt).TotalMinutes;
        return 0f;
    }

    private float CalculateAvgTimeBetween(List<EventRecord> events)
    {
        if (events.Count < 2) return 0f;

        var intervals = new List<double>();
        for (int i = 1; i < events.Count; i++)
        {
            intervals.Add((events[i].EventTime - events[i - 1].EventTime).TotalSeconds);
        }

        return intervals.Any() ? (float)intervals.Average() : 0f;
    }

    private float CalculateDeviceAge(DeviceContext context)
    {
        try
        {
            var installDate = DateTimeOffset.FromUnixTimeMilliseconds(context.Application.InstallTimestamp);
            return (float)(DateTime.UtcNow - installDate).TotalDays;
        }
        catch
        {
            return 0f;
        }
    }

    private float CalculateInstallToSession(DeviceContext context, DateTime sessionTime)
    {
        try
        {
            var installDate = DateTimeOffset.FromUnixTimeMilliseconds(context.Application.InstallTimestamp);
            return (float)(sessionTime - installDate).TotalMinutes;
        }
        catch
        {
            return 0f;
        }
    }

    private float SafeDivide(float numerator, float denominator)
    {
        return denominator > 0 ? numerator / denominator : 0f;
    }

    // ==================== EVENT COUNTING ====================

    private int CountOtpFailures(List<EventRecord> events)
    {
        return events.Count(e =>
            e.EventName == "add_card_otp_unsuccess_entered" ||
            e.EventName == "otp_page_error");
    }

    private int CountOtpSuccesses(List<EventRecord> events)
    {
        return events.Count(e =>
            e.EventName == "add_card_otp_success_entered" ||
            e.EventName == "p2p_otp_success");
    }

    private float CalculateOtpSuccessRate(List<EventRecord> events)
    {
        var successes = CountOtpSuccesses(events);
        var failures = CountOtpFailures(events);
        var total = successes + failures;

        return total > 0 ? (float)successes / total : 1f;
    }

    private int CountCardAdditions(List<EventRecord> events)
    {
        return events.Count(e => e.EventName == "add_card_otp_success_entered");
    }

    private int CountP2PTransfers(List<EventRecord> events)
    {
        return events.Count(e => e.EventName == "p2p_otp_success");
    }

    private int CountPayments(List<EventRecord> events)
    {
        return events.Count(e => e.EventName == "payment_confirm");
    }

    private float CalculateTransferToPaymentRatio(List<EventRecord> events)
    {
        var transfers = CountP2PTransfers(events);
        var payments = CountPayments(events);

        if (payments == 0) return transfers > 0 ? 10f : 0f;
        return (float)transfers / payments;
    }

    // ==================== MULTI-ACCOUNTING HELPERS ====================

    private float CalculateSwitchesPerDay(int totalSwitches, int days)
    {
        return days > 0 ? (float)totalSwitches / days : 0f;
    }

    private float CalculateSameActionScore(List<UserBehaviorPattern> behaviors)
    {
        if (behaviors.Count < 2) return 0f;

        // Calculate how similar the user behaviors are (0 = different, 1 = identical)
        var cardAdds = behaviors.Select(b => b.CardAdditions).ToList();
        var p2ps = behaviors.Select(b => b.P2PTransfers).ToList();
        var payments = behaviors.Select(b => b.Payments).ToList();

        var cardStdDev = CalculateStdDev(cardAdds);
        var p2pStdDev = CalculateStdDev(p2ps);
        var paymentStdDev = CalculateStdDev(payments);

        // Low standard deviation = similar behavior = high score
        var avgStdDev = (cardStdDev + p2pStdDev + paymentStdDev) / 3f;
        return avgStdDev < 1 ? 1f : 1f / avgStdDev;
    }

    private float CalculateStdDev(List<int> values)
    {
        if (values.Count < 2) return 0f;

        var avg = values.Average();
        var sumOfSquares = values.Sum(v => Math.Pow(v - avg, 2));
        return (float)Math.Sqrt(sumOfSquares / values.Count);
    }

    // ==================== MULTI-DEVICING HELPERS ====================

    private float IsAlwaysNewDevice(MultiDevicingHistory history)
    {
        // If user has used many devices and most are new, it's suspicious
        if (history.UniqueDevices_30d < 3) return 0f;

        var newDeviceRatio = (float)history.NewDeviceLogins_7d / history.UniqueDevices_7d;
        return newDeviceRatio > 0.8f ? 1f : 0f;
    }
}
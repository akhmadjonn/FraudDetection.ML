using Microsoft.ML.Data;

namespace FraudDetection.ML.Models;

/// <summary>
/// Complete feature set for fraud detection including:
/// - Session features
/// - Device features  
/// - Security features
/// - Behavioral features
/// - Multi-accounting features (NEW)
/// - Multi-devicing features (NEW)
/// </summary>
public class FraudFeatures
{
    // ==================== IDENTIFIERS (Not used in ML) ====================
    public string SessionId { get; set; } = string.Empty;
    public Guid ProfileId { get; set; }
    public string DeviceKey { get; set; } = string.Empty;
    public Guid GlobalDeviceId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string PhoneNumber { get; set; } = string.Empty;

    // ==================== SESSION FEATURES ====================
    [LoadColumn(0)] public float SessionDuration { get; set; }
    [LoadColumn(1)] public float EventCount { get; set; }
    [LoadColumn(2)] public float AverageTimeBetweenEvents { get; set; }
    [LoadColumn(3)] public float SessionStartHour { get; set; }
    [LoadColumn(4)] public float DayOfWeek { get; set; }
    [LoadColumn(5)] public float SessionNumber { get; set; }

    // ==================== DEVICE FEATURES ====================
    [LoadColumn(6)] public float DeviceAgeInDays { get; set; }
    [LoadColumn(7)] public float InstallToSessionMinutes { get; set; }
    [LoadColumn(8)] public float BatteryLevel { get; set; }
    [LoadColumn(9)] public float RamFreeRatio { get; set; }
    [LoadColumn(10)] public float StorageFreeRatio { get; set; }

    // ==================== SECURITY FEATURES ====================
    [LoadColumn(11)] public float IsEmulator { get; set; }
    [LoadColumn(12)] public float IsRooted { get; set; }
    [LoadColumn(13)] public float IsVpn { get; set; }
    [LoadColumn(14)] public float IsCloned { get; set; }
    [LoadColumn(15)] public float IsRoaming { get; set; }

    // ==================== BEHAVIORAL FEATURES ====================
    [LoadColumn(16)] public float OtpFailureCount { get; set; }
    [LoadColumn(17)] public float OtpSuccessCount { get; set; }
    [LoadColumn(18)] public float OtpSuccessRate { get; set; }
    [LoadColumn(19)] public float CardAdditionCount { get; set; }
    [LoadColumn(20)] public float P2PTransferCount { get; set; }
    [LoadColumn(21)] public float PaymentCount { get; set; }
    [LoadColumn(22)] public float TransferToPaymentRatio { get; set; }

    // ==================== HISTORICAL FEATURES ====================
    [LoadColumn(23)] public float TotalSessionsForDevice { get; set; }
    [LoadColumn(24)] public float UniqueIpCount { get; set; }
    [LoadColumn(25)] public float DifferentCarrierCount { get; set; }
    [LoadColumn(26)] public float ConnectionIsMobile { get; set; }

    // ==================== MULTI-ACCOUNTING FEATURES (Device-Level) ====================
    [LoadColumn(27)] public float UniqueUserIdsOnDevice_24h { get; set; }
    [LoadColumn(28)] public float UniqueUserIdsOnDevice_7d { get; set; }
    [LoadColumn(29)] public float UniqueUserIdsOnDevice_30d { get; set; }
    [LoadColumn(30)] public float UniquePhoneNumbersOnDevice_7d { get; set; }
    [LoadColumn(31)] public float UserSwitchesPerDay { get; set; }
    [LoadColumn(32)] public float NewUserCreationsOnDevice_24h { get; set; }
    [LoadColumn(33)] public float NewUserCreationsOnDevice_7d { get; set; }
    [LoadColumn(34)] public float AccountSwitchingVelocity { get; set; } // Avg minutes between switches
    [LoadColumn(35)] public float SameActionPatternScore { get; set; } // 0-1, how similar are user behaviors

    // ==================== MULTI-DEVICING FEATURES (User-Level) ====================
    [LoadColumn(36)] public float DevicesPerUser_24h { get; set; }
    [LoadColumn(37)] public float DevicesPerUser_7d { get; set; }
    [LoadColumn(38)] public float DevicesPerUser_30d { get; set; }
    [LoadColumn(39)] public float NewDeviceLoginsForUser_7d { get; set; }
    [LoadColumn(40)] public float DeviceSwitchesPerDayForUser { get; set; }
    [LoadColumn(41)] public float AlwaysNewDeviceFlag { get; set; } // 1 if user always uses new devices
    [LoadColumn(42)] public float GeographicJumpCount_24h { get; set; }
    [LoadColumn(43)] public float IpChangesForUser_24h { get; set; }
    [LoadColumn(44)] public float IpChangesForUser_7d { get; set; }
    [LoadColumn(45)] public float CarrierChangesForUser_7d { get; set; }
    [LoadColumn(46)] public float SuspiciousVelocityFlag { get; set; } // 1 if impossible travel detected
}
namespace FraudDetection.ML.Models;

public class SessionRecord
{
    public Guid Id { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public Guid? GlobalId { get; set; }  // Nullable - not always present
    public Guid GlobalDeviceId { get; set; }
    public string DeviceContext { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpireAt { get; set; }
    public string DeviceKey { get; set; } = string.Empty;
    public string AppSetId { get; set; } = string.Empty;
    public string MetaData { get; set; } = string.Empty;
    public Guid? ProfileId { get; set; }  // Nullable - not always coming from client
}

public class EventRecord
{
    public Guid Id { get; set; }  // UUID in ClickHouse
    public string SessionId { get; set; } = string.Empty;
    public string EventName { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string EventParams { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }  // Using CreatedAt instead of EventTime
}

public class MetaDataInfo
{
    public string PhoneNumber { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;

    public bool IsValid => !string.IsNullOrWhiteSpace(UserId) ||
                          !string.IsNullOrWhiteSpace(PhoneNumber);
}

public class DeviceHistory
{
    public int TotalSessions { get; set; }
    public int UniqueIpCount { get; set; }
    public int DifferentCarrierCount { get; set; }
}

public class MultiAccountingHistory
{
    public int UniqueUserIds_24h { get; set; }
    public int UniqueUserIds_7d { get; set; }
    public int UniqueUserIds_30d { get; set; }
    public int UniquePhoneNumbers_7d { get; set; }
    public int UserSwitches { get; set; }
    public int NewUsers_24h { get; set; }
    public int NewUsers_7d { get; set; }
    public float AvgMinutesBetweenSwitches { get; set; }
    public List<UserBehaviorPattern> UserBehaviors { get; set; } = new();
}

public class MultiDevicingHistory
{
    public int UniqueDevices_24h { get; set; }
    public int UniqueDevices_7d { get; set; }
    public int UniqueDevices_30d { get; set; }
    public int NewDeviceLogins_7d { get; set; }
    public int DeviceSwitches { get; set; }
    public int TotalDevicesEverUsed { get; set; }
    public int GeographicJumps_24h { get; set; }
    public int IpChanges_24h { get; set; }
    public int IpChanges_7d { get; set; }
    public int CarrierChanges_7d { get; set; }
    public bool HasImpossibleTravel { get; set; }
    public List<DeviceLoginInfo> RecentDevices { get; set; } = new();
}

public class UserBehaviorPattern
{
    public string UserId { get; set; } = string.Empty;
    public int CardAdditions { get; set; }
    public int P2PTransfers { get; set; }
    public int Payments { get; set; }
    public int OtpFailures { get; set; }
}

public class DeviceLoginInfo
{
    public string DeviceKey { get; set; } = string.Empty;
    public Guid GlobalDeviceId { get; set; }  // UUID in ClickHouse
    public DateTime LoginTime { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string Carrier { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
}

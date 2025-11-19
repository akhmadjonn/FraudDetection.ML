using System.Text.Json.Serialization;

namespace FraudDetection.ML.Models;

public class DeviceContext
{
    [JsonPropertyName("Device")]
    public Device Device { get; set; } = new();

    [JsonPropertyName("Security")]
    public Security Security { get; set; } = new();

    [JsonPropertyName("Network")]
    public Network Network { get; set; } = new();

    [JsonPropertyName("Application")]
    public Application Application { get; set; } = new();

    [JsonPropertyName("Os")]
    public Os Os { get; set; } = new();
}

public class Device
{
    [JsonPropertyName("BatteryLevel")]
    public int BatteryLevel { get; set; }

    [JsonPropertyName("RamTotal")]
    public int RamTotal { get; set; }

    [JsonPropertyName("RamFree")]
    public int RamFree { get; set; }

    [JsonPropertyName("StorageTotal")]
    public int StorageTotal { get; set; }

    [JsonPropertyName("StorageFree")]
    public int StorageFree { get; set; }

    [JsonPropertyName("Manufacturer")]
    public string Manufacturer { get; set; } = string.Empty;

    [JsonPropertyName("Model")]
    public string Model { get; set; } = string.Empty;
}

public class Security
{
    [JsonPropertyName("RootStatus")]
    public bool RootStatus { get; set; }

    [JsonPropertyName("EmulatorStatus")]
    public bool EmulatorStatus { get; set; }

    [JsonPropertyName("CloneStatus")]
    public bool CloneStatus { get; set; }
}

public class Network
{
    [JsonPropertyName("VpnStatus")]
    public bool VpnStatus { get; set; }

    [JsonPropertyName("RoamingStatus")]
    public bool RoamingStatus { get; set; }

    [JsonPropertyName("ConnectionType")]
    public string ConnectionType { get; set; } = string.Empty;

    [JsonPropertyName("XClientIp")]
    public string XClientIp { get; set; } = string.Empty;

    [JsonPropertyName("OperatorName")]
    public string OperatorName { get; set; } = string.Empty;

    [JsonPropertyName("Mcc")]
    public string Mcc { get; set; } = string.Empty;

    [JsonPropertyName("Mnc")]
    public string Mnc { get; set; } = string.Empty;
}

public class Application
{
    [JsonPropertyName("InstallTimestamp")]
    public long InstallTimestamp { get; set; }

    [JsonPropertyName("AppVersionName")]
    public string AppVersionName { get; set; } = string.Empty;
}

public class Os
{
    [JsonPropertyName("OsName")]
    public string OsName { get; set; } = string.Empty;

    [JsonPropertyName("OsVersion")]
    public string OsVersion { get; set; } = string.Empty;
}
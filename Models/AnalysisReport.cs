namespace FraudDetection.ML.Models;

public class DailyAnalysisReport
{
    public DateTime ReportDate { get; set; }
    public int TotalSessionsAnalyzed { get; set; }

    // Risk Distribution
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }

    // Fraud Type Distribution
    public int MultiAccountingCount { get; set; }
    public int MultiDevicingCount { get; set; }
    public int AccountTakeoverCount { get; set; }
    public int ImpossibleTravelCount { get; set; }

    // Patterns
    public List<SuspiciousPattern> PatternsFound { get; set; } = new();

    // Cluster Analysis
    public List<ClusterSummary> ClusterSummaries { get; set; } = new();

    // Top Cases
    public List<FraudAnalysisResult> TopSuspiciousSessions { get; set; } = new();
    public List<MultiAccountingCase> TopMultiAccountingDevices { get; set; } = new();
    public List<MultiDevicingCase> TopMultiDevicingUsers { get; set; } = new();
}

public class SuspiciousPattern
{
    public string PatternName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int OccurrenceCount { get; set; }
    public List<string> CommonCharacteristics { get; set; } = new();
    public string RecommendedAction { get; set; } = string.Empty;
}

public class ClusterSummary
{
    public uint ClusterId { get; set; }
    public int SessionCount { get; set; }
    public float PercentageOfTotal { get; set; }
    public Dictionary<string, float> AverageFeatures { get; set; } = new();
    public string Interpretation { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}

public class MultiAccountingCase
{
    public string GlobalDeviceId { get; set; } = string.Empty;
    public string DeviceKey { get; set; } = string.Empty;
    public int UniqueUserCount { get; set; }
    public List<string> UserIds { get; set; } = new();
    public List<string> PhoneNumbers { get; set; } = new();
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public float RiskScore { get; set; }
}

public class MultiDevicingCase
{
    public string UserId { get; set; } = string.Empty;
    public string PhoneNumber { get; set; } = string.Empty;
    public int UniqueDeviceCount { get; set; }
    public List<string> DeviceKeys { get; set; } = new();
    public bool HasImpossibleTravel { get; set; }
    public int GeographicJumps { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public float RiskScore { get; set; }
}
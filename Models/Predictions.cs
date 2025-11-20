using Microsoft.ML.Data;

namespace FraudDetection.ML.Models;

public class AnomalyPrediction
{
    [ColumnName("PredictedLabel")]
    public bool IsAnomaly { get; set; }

    [ColumnName("Score")]
    public float AnomalyScore { get; set; }
}

public class ClusterPrediction
{
    [ColumnName("PredictedLabel")]
    public uint ClusterId { get; set; }

    [ColumnName("Score")]
    public float[] Distances { get; set; } = Array.Empty<float>();
}

public class FraudAnalysisResult
{
    public string SessionId { get; set; } = string.Empty;
    public Guid? ProfileId { get; set; }  // Nullable - not always present
    public string DeviceKey { get; set; } = string.Empty;
    public Guid GlobalDeviceId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string PhoneNumber { get; set; } = string.Empty;
    public DateTime AnalyzedAt { get; set; }

    // ML Scores
    public float AnomalyScore { get; set; }
    public bool IsAnomaly { get; set; }
    public uint ClusterId { get; set; }
    public string RiskLevel { get; set; } = "LOW"; // LOW, MEDIUM, HIGH, CRITICAL

    // Fraud Types Detected
    public bool IsMultiAccounting { get; set; }
    public bool IsMultiDevicing { get; set; }
    public bool IsAccountTakeover { get; set; }
    public bool IsImpossibleTravel { get; set; }

    // Reasons
    public List<string> SuspiciousReasons { get; set; } = new();

    // Features for reference
    public FraudFeatures Features { get; set; } = new();
}
namespace FraudDetection.ML.Models;

/// <summary>
/// Represents a decision about whether to send an alert and which fraud types to highlight
/// </summary>
public class AlertDecision
{
    /// <summary>
    /// Whether an alert should be sent
    /// </summary>
    public bool ShouldSend { get; set; }

    /// <summary>
    /// Reason for the decision (for logging/debugging)
    /// </summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>
    /// List of NEW fraud types that should be alerted on
    /// </summary>
    public List<string> FraudTypesToAlert { get; set; } = new();

    /// <summary>
    /// When this decision was made
    /// </summary>
    public DateTime DecisionTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// All fraud types detected (including throttled ones)
    /// </summary>
    public List<string> AllDetectedFraudTypes { get; set; } = new();

    /// <summary>
    /// Fraud types that were throttled
    /// </summary>
    public List<string> ThrottledFraudTypes { get; set; } = new();
}

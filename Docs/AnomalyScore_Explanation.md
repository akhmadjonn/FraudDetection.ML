# AnomalyScore Column Explanation

## What is AnomalyScore?

The `AnomalyScore` column in the `FraudAnalysisResults` table stores the anomaly detection score from ML.NET's RandomizedPCA algorithm.

## Understanding the Score

### ML.NET RandomizedPCA Score Range
- **ML.NET RandomizedPCA** produces scores typically in the range of **0.0 to 1.0+**
- Higher values indicate **MORE anomalous** (suspicious) behavior
- Lower values indicate **LESS anomalous** (normal) behavior

**Note:** This is different from Python's Isolation Forest which produces scores from -1 to +1.

### Score Interpretation

| Score Range | Risk Level | Interpretation | Action |
|-------------|------------|----------------|---------|
| 0.0 - 0.3 | LOW | Normal behavior | Monitor |
| 0.3 - 0.5 | MEDIUM | Slightly suspicious | Review |
| 0.5 - 0.7 | HIGH | Suspicious activity | Alert |
| 0.7+ | CRITICAL | Highly anomalous | Immediate action |

### Example Database Values

```sql
SessionId   | UserId    | AnomalyScore | RiskLevel | IsMultiAccounting
------------|-----------|--------------|-----------|------------------
sess_001    | user_123  | 0.25         | LOW       | false
sess_002    | user_456  | 0.68         | HIGH      | true
sess_003    | user_789  | 0.15         | LOW       | false
sess_004    | user_321  | 0.92         | CRITICAL  | true
```

## Why Were Values NaN?

### Root Causes

1. **Invalid Feature Values**
   - Division by zero in feature calculations
   - Missing or null values in historical data
   - Infinite values from calculations

2. **ML Model Issues**
   - Model receiving NaN/Inf features
   - RandomizedPCA unable to process invalid input
   - No validation before prediction

3. **No Validation Layer**
   - Features not checked before ML processing
   - Scores not validated before database insertion

## Fixes Implemented

### 1. Enhanced SafeDivide Method
```csharp
// Now checks for NaN/Inf in both numerator and denominator
private float SafeDivide(float numerator, float denominator)
{
    if (float.IsNaN(numerator) || float.IsInfinity(numerator))
        return 0f;
    if (float.IsNaN(denominator) || float.IsInfinity(denominator) || denominator == 0)
        return 0f;

    var result = numerator / denominator;
    if (float.IsNaN(result) || float.IsInfinity(result))
        return 0f;

    return result;
}
```

### 2. Feature Validation
```csharp
// Validates all float features before prediction
private void ValidateAndCleanFeatures(FraudFeatures features)
{
    var properties = typeof(FraudFeatures).GetProperties()
        .Where(p => p.PropertyType == typeof(float));

    foreach (var prop in properties)
    {
        var value = (float)prop.GetValue(features)!;
        if (float.IsNaN(value) || float.IsInfinity(value))
        {
            prop.SetValue(features, 0f);
        }
    }
}
```

### 3. Prediction Validation
```csharp
// Validates ML model output
var prediction = _predictionEngine.Predict(features);
if (float.IsNaN(prediction.AnomalyScore) || float.IsInfinity(prediction.AnomalyScore))
{
    prediction.AnomalyScore = 0f;
    prediction.IsAnomaly = false;
}
```

### 4. Database Insertion Validation
```csharp
// Final check before saving to database
if (float.IsNaN(result.AnomalyScore) || float.IsInfinity(result.AnomalyScore))
{
    result.AnomalyScore = 0f;
}
```

## How to Fix Existing NaN Values

Run the SQL script located at: `Scripts/fix_nan_anomaly_scores.sql`

```bash
clickhouse-client --queries-file Scripts/fix_nan_anomaly_scores.sql
```

Or use the web interface at your ClickHouse installation.

## Monitoring AnomalyScore

### Query to Check for Invalid Values
```sql
SELECT
    COUNT(*) as Total,
    countIf(isNaN(AnomalyScore)) as NaN_Count,
    countIf(isInf(AnomalyScore)) as Inf_Count,
    countIf(AnomalyScore = 0) as Zero_Count
FROM FraudAnalysisResults;
```

### Query to See Score Distribution
```sql
SELECT
    CASE
        WHEN AnomalyScore = 0 THEN '0 (Default)'
        WHEN AnomalyScore <= 0.3 THEN '0-0.3 (Low)'
        WHEN AnomalyScore <= 0.5 THEN '0.3-0.5 (Medium)'
        WHEN AnomalyScore <= 0.7 THEN '0.5-0.7 (High)'
        ELSE '0.7+ (Critical)'
    END as ScoreRange,
    COUNT(*) as Count,
    round(AVG(AnomalyScore), 4) as AvgScore
FROM FraudAnalysisResults
GROUP BY ScoreRange
ORDER BY ScoreRange;
```

## Expected Behavior After Fix

After implementing these fixes, you should see:

1. ✅ **No more NaN values** in the database
2. ✅ **Valid numeric scores** between 0.0 and 1.0+
3. ✅ **Warning logs** when invalid features are detected
4. ✅ **Automatic correction** to 0.0 for invalid cases

## Correlation with Other Fields

AnomalyScore should correlate with:

- **RiskLevel**: Higher scores → Higher risk levels (HIGH, CRITICAL)
- **IsMultiAccounting**: Often has higher AnomalyScore
- **IsMultiDevicing**: Often has higher AnomalyScore
- **SuspiciousReasons**: More reasons → Higher AnomalyScore

Example:
```sql
SELECT
    RiskLevel,
    round(AVG(AnomalyScore), 4) as AvgAnomalyScore,
    COUNT(*) as Count
FROM FraudAnalysisResults
WHERE AnomalyScore > 0
GROUP BY RiskLevel
ORDER BY AvgAnomalyScore DESC;
```

Expected output:
```
RiskLevel  | AvgAnomalyScore | Count
-----------|-----------------|-------
CRITICAL   | 0.8234          | 145
HIGH       | 0.6512          | 423
MEDIUM     | 0.4123          | 1256
LOW        | 0.2156          | 8432
```

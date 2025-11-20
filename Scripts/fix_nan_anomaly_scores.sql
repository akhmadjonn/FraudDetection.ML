-- ═══════════════════════════════════════════════════════════════════
-- Fix NaN AnomalyScore values in FraudAnalysisResults table
-- ═══════════════════════════════════════════════════════════════════

-- Step 1: Check how many NaN values exist
SELECT
    'Total Records' as Metric,
    COUNT(*) as Count
FROM FraudAnalysisResults
UNION ALL
SELECT
    'Records with NaN AnomalyScore',
    countIf(isNaN(AnomalyScore))
FROM FraudAnalysisResults
UNION ALL
SELECT
    'Records with Inf AnomalyScore',
    countIf(isInf(AnomalyScore))
FROM FraudAnalysisResults
UNION ALL
SELECT
    'Valid AnomalyScore Records',
    countIf(NOT isNaN(AnomalyScore) AND NOT isInf(AnomalyScore))
FROM FraudAnalysisResults;

-- Step 2: View sample of records with NaN
SELECT
    SessionId,
    UserId,
    PhoneNumber,
    AnomalyScore,
    RiskLevel,
    AnalyzedAt
FROM FraudAnalysisResults
WHERE isNaN(AnomalyScore) OR isInf(AnomalyScore)
LIMIT 10;

-- Step 3: Fix NaN/Inf values - Create a new table with corrected values
-- Note: ClickHouse doesn't support UPDATE on MergeTree directly
-- We need to use ALTER TABLE ... UPDATE or recreate the table

-- Option A: Using ALTER TABLE UPDATE (Available in ClickHouse 19.3+)
ALTER TABLE FraudAnalysisResults
UPDATE AnomalyScore = 0.0
WHERE isNaN(AnomalyScore) OR isInf(AnomalyScore);

-- Option B: If ALTER UPDATE doesn't work, use INSERT ... SELECT pattern
-- Step 3.1: Create temporary table with correct values
CREATE TABLE IF NOT EXISTS FraudAnalysisResults_Fixed
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
ORDER BY (AnalyzedAt, SessionId);

-- Step 3.2: Copy data with fixed AnomalyScore
INSERT INTO FraudAnalysisResults_Fixed
SELECT
    SessionId,
    ProfileId,
    DeviceKey,
    GlobalDeviceId,
    UserId,
    PhoneNumber,
    AnalyzedAt,
    if(isNaN(AnomalyScore) OR isInf(AnomalyScore), 0.0, AnomalyScore) as AnomalyScore,
    IsAnomaly,
    ClusterId,
    RiskLevel,
    IsMultiAccounting,
    IsMultiDevicing,
    IsAccountTakeover,
    IsImpossibleTravel,
    SuspiciousReasons,
    Features
FROM FraudAnalysisResults;

-- Step 3.3: Verify the fix
SELECT
    'Fixed Table - Total Records' as Metric,
    COUNT(*) as Count
FROM FraudAnalysisResults_Fixed
UNION ALL
SELECT
    'Fixed Table - Records with NaN',
    countIf(isNaN(AnomalyScore))
FROM FraudAnalysisResults_Fixed
UNION ALL
SELECT
    'Fixed Table - Valid Records',
    countIf(NOT isNaN(AnomalyScore) AND NOT isInf(AnomalyScore))
FROM FraudAnalysisResults_Fixed;

-- Step 3.4: Backup old table and rename
-- RENAME TABLE FraudAnalysisResults TO FraudAnalysisResults_Backup;
-- RENAME TABLE FraudAnalysisResults_Fixed TO FraudAnalysisResults;

-- Step 4: Verify distribution of AnomalyScore values after fix
SELECT
    CASE
        WHEN AnomalyScore = 0 THEN '0 (Default/Fixed)'
        WHEN AnomalyScore > 0 AND AnomalyScore <= 0.3 THEN '0-0.3 (Low)'
        WHEN AnomalyScore > 0.3 AND AnomalyScore <= 0.5 THEN '0.3-0.5 (Medium)'
        WHEN AnomalyScore > 0.5 AND AnomalyScore <= 0.7 THEN '0.5-0.7 (High)'
        WHEN AnomalyScore > 0.7 THEN '0.7+ (Critical)'
        ELSE 'Other'
    END as ScoreRange,
    COUNT(*) as Count,
    round(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM FraudAnalysisResults), 2) as Percentage
FROM FraudAnalysisResults
GROUP BY ScoreRange
ORDER BY ScoreRange;

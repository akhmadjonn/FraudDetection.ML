-- ═══════════════════════════════════════════════════════════════════
-- Diagnostic Script: AnomalyScore Investigation
-- ═══════════════════════════════════════════════════════════════════

-- 1. Check total sessions available for training
SELECT
    'Total Sessions (Last 7 Days)' as Metric,
    COUNT(*) as Count,
    MIN(CreatedAt) as OldestSession,
    MAX(CreatedAt) as NewestSession
FROM Sessions
WHERE CreatedAt >= now() - INTERVAL 7 DAY;

-- 2. Check if FraudAnalysisResults table exists and has data
SELECT
    'Total Analysis Results' as Metric,
    COUNT(*) as Count,
    MIN(AnalyzedAt) as FirstAnalysis,
    MAX(AnalyzedAt) as LastAnalysis
FROM FraudAnalysisResults;

-- 3. Check AnomalyScore distribution
SELECT
    CASE
        WHEN AnomalyScore = 0 THEN '0 (Default/Issue)'
        WHEN AnomalyScore > 0 AND AnomalyScore <= 0.3 THEN '0-0.3 (Low)'
        WHEN AnomalyScore > 0.3 AND AnomalyScore <= 0.5 THEN '0.3-0.5 (Medium)'
        WHEN AnomalyScore > 0.5 AND AnomalyScore <= 0.7 THEN '0.5-0.7 (High)'
        WHEN AnomalyScore > 0.7 THEN '0.7+ (Critical)'
        ELSE 'NaN/Inf'
    END as ScoreRange,
    COUNT(*) as Count,
    round(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM FraudAnalysisResults), 2) as Percentage
FROM FraudAnalysisResults
GROUP BY ScoreRange
ORDER BY ScoreRange;

-- 4. Check if there are ANY non-zero scores
SELECT
    'Non-Zero Scores' as Metric,
    COUNT(*) as Count
FROM FraudAnalysisResults
WHERE AnomalyScore > 0;

-- 5. Sample of results to see what's happening
SELECT
    SessionId,
    UserId,
    PhoneNumber,
    AnomalyScore,
    IsAnomaly,
    RiskLevel,
    IsMultiAccounting,
    IsMultiDevicing,
    AnalyzedAt
FROM FraudAnalysisResults
ORDER BY AnalyzedAt DESC
LIMIT 20;

-- 6. Check risk levels distribution (should correlate with AnomalyScore)
SELECT
    RiskLevel,
    COUNT(*) as Count,
    round(AVG(AnomalyScore), 4) as AvgScore,
    round(MIN(AnomalyScore), 4) as MinScore,
    round(MAX(AnomalyScore), 4) as MaxScore
FROM FraudAnalysisResults
GROUP BY RiskLevel
ORDER BY AvgScore DESC;

-- 7. Check if there are fraud indicators but still 0 score (MODEL ISSUE)
SELECT
    'Sessions with Fraud Indicators BUT AnomalyScore=0' as Issue,
    COUNT(*) as Count
FROM FraudAnalysisResults
WHERE AnomalyScore = 0
  AND (IsMultiAccounting = 1 OR IsMultiDevicing = 1 OR IsAccountTakeover = 1);

# Fraud-Type-Aware Alert Throttling

## Overview

The fraud detection system now implements **intelligent alert throttling** that prevents alert spam while ensuring you're notified of **NEW fraud patterns** as they emerge.

## The Problem (Before)

**Without throttling**, every high/critical session triggers an alert:

```
10:00 - Session #1: Multi-Accounting detected → Alert sent ✓
10:05 - Session #2: Multi-Accounting (same device) → Alert sent ✓ (DUPLICATE!)
10:10 - Session #3: Multi-Accounting (same device) → Alert sent ✓ (DUPLICATE!)
10:15 - Session #4: Multi-Accounting + Impossible Travel → Alert sent ✓ (NEW PATTERN HIDDEN!)
```

**Problems:**
- 🔴 Alert spam for same fraud pattern
- 🔴 Can't distinguish between repeated patterns and NEW threats
- 🔴 Important escalations get lost in noise

---

## The Solution (After)

**Fraud-Type-Aware Throttling** tracks each fraud type separately:

```
10:00 - Session #1: Multi-Accounting detected
        → Alert SENT ✓ (NEW fraud type)
        → Throttle key: "device:abc123:CRITICAL:MultiAccounting"

10:05 - Session #2: Multi-Accounting (same device)
        → Alert THROTTLED ✗ (already alerted within 24h)

10:10 - Session #3: Multi-Accounting (same device)
        → Alert THROTTLED ✗ (already alerted within 24h)

10:15 - Session #4: Multi-Accounting + Impossible Travel
        → Alert SENT ✓ (NEW fraud type: ImpossibleTravel!)
        → Throttle key: "user:user123:CRITICAL:ImpossibleTravel"
```

**Benefits:**
- ✅ No spam from repeated patterns
- ✅ Always notified of NEW fraud types
- ✅ Escalating behavior is immediately visible
- ✅ All sessions still saved to ClickHouse

---

## How It Works

### 1. Fraud Type Detection

Four fraud types are tracked independently:
- **Multi-Accounting**: Multiple users on same device
- **Multi-Devicing**: Single user across many devices
- **Account Takeover**: User only uses brand new devices
- **Impossible Travel**: User in different locations < 2 hours apart

### 2. Throttle Key Generation

Each fraud type gets a unique throttle key:

**Device-based fraud** (Multi-Accounting, Account Takeover):
```
Format: device:{DeviceKey}:{RiskLevel}:{FraudType}
Example: device:abc123:CRITICAL:MultiAccounting
```

**User-based fraud** (Multi-Devicing, Impossible Travel):
```
Format: user:{UserId}:{RiskLevel}:{FraudType}
Example: user:user456:HIGH:ImpossibleTravel
```

### 3. Alert Decision Logic

```csharp
For each HIGH/CRITICAL session:
    1. Extract detected fraud types
    2. For each fraud type:
        a. Check if alert sent within throttle window (24h default)
        b. If NO → This is a NEW fraud type
        c. If YES → This fraud type was already alerted
    3. If any NEW fraud types found:
        → Send alert highlighting NEW patterns
        → Record alert in AlertHistory table
    4. Otherwise:
        → Throttle (no alert sent)
    5. ALWAYS save session to FraudAnalysisResults
```

---

## Alert History Table

Tracks sent alerts in ClickHouse:

```sql
CREATE TABLE AlertHistory
(
    AlertId String,              -- Unique alert ID
    SessionId String,            -- Triggering session
    DeviceKey String,            -- Device involved
    GlobalDeviceId String,       -- Device UUID
    UserId String,               -- User involved
    PhoneNumber String,          -- User phone
    RiskLevel String,            -- CRITICAL/HIGH
    FraudTypes Array(String),    -- Fraud type(s) alerted
    SentAt DateTime,             -- When alert was sent
    ThrottleKey String           -- Unique throttle key
)
ENGINE = MergeTree()
ORDER BY (SentAt, DeviceKey, UserId)
TTL SentAt + INTERVAL 30 DAY    -- Auto-cleanup after 30 days
```

---

## Configuration

In `appsettings.json`:

```json
{
  "Alerts": {
    "ThrottleWindowHours": 24
  }
}
```

**Recommendations:**
- **24 hours**: Good balance for most use cases
- **12 hours**: More frequent updates for high-risk environments
- **48 hours**: Reduce alert frequency for low-volume systems

---

## Example Scenarios

### Scenario 1: Escalating Threat

```
Day 1, 10:00 AM - Device "ABC123"
├─ Fraud: Multi-Accounting (3 users)
├─ Risk: HIGH
└─ Alert: SENT ✓ "3 users detected on device"

Day 1, 2:00 PM - Same device
├─ Fraud: Multi-Accounting (3 users, no change)
├─ Risk: HIGH
└─ Alert: THROTTLED ✗ (same pattern)

Day 1, 6:00 PM - Same device
├─ Fraud: Multi-Accounting (8 users!) + Impossible Travel (NEW!)
├─ Risk: CRITICAL (escalated!)
└─ Alert: SENT ✓ "NEW PATTERNS DETECTED"
    ├─ ⚡ Impossible Travel (NEW)
    └─ Previously Detected: Multi-Accounting
```

### Scenario 2: Different Fraud Types on Different Entities

```
10:00 - Device "DEV1", User "Alice"
├─ Fraud: Multi-Accounting
└─ Alert: SENT ✓ (throttle key: device:DEV1:HIGH:MultiAccounting)

10:30 - Device "DEV2", User "Alice"
├─ Fraud: Multi-Devicing (Alice now on 4+ devices!)
└─ Alert: SENT ✓ (throttle key: user:Alice:HIGH:MultiDevicing)
    Note: Different throttle key, so not throttled!
```

---

## Monitoring

### Check Alert Statistics

```csharp
var stats = await alertHistoryService.GetAlertStatisticsAsync(DateTime.UtcNow.AddDays(-7));

Console.WriteLine($"Total Alerts: {stats.TotalAlerts}");
Console.WriteLine($"Multi-Accounting: {stats.MultiAccountingAlerts}");
Console.WriteLine($"Impossible Travel: {stats.ImpossibleTravelAlerts}");
```

### View Logs

```
🚨 CRITICAL risk detected! Session: sess123, User: +998901234567, Score: 0.95,
   NEW Fraud Types: ImpossibleTravel

⏸️ Alert throttled for session sess124 - all fraud types already alerted within window
```

---

## Key Points

✅ **All sessions are ALWAYS saved** to `FraudAnalysisResults` table (no data loss)
✅ **Alerts are only throttled** - the underlying fraud detection runs every 10 seconds
✅ **Each fraud type tracked separately** - new patterns always trigger alerts
✅ **Configurable throttle window** - adjust based on your needs
✅ **Automatic cleanup** - AlertHistory uses TTL (30 days)

---

## Files Modified

1. **AlertHistoryService.cs** (NEW)
   - Manages alert history and throttling logic
   - Builds unique throttle keys per fraud type

2. **RealTimeScoringJob.cs**
   - Line 63: Added AlertHistoryService injection
   - Line 122-130: Check for new fraud types before alerting
   - Line 113: ALWAYS saves to database regardless of alert

3. **NotificationService.cs**
   - Line 27: Updated to accept newFraudTypes parameter
   - Line 59-161: Enhanced alert formatting to highlight NEW patterns

4. **Program.cs**
   - Line 22: Registered AlertHistoryService
   - Line 45-49: Initialize AlertHistory table on startup

5. **appsettings.json**
   - Lines 8-11: Added Alerts configuration section

---

## Testing Recommendations

1. **Test New Fraud Detection:**
   - Generate session with Multi-Accounting
   - Verify alert sent
   - Generate another session with same fraud
   - Verify alert throttled

2. **Test Escalation:**
   - Generate session with Multi-Accounting
   - After 1 hour, add Impossible Travel
   - Verify alert sent for NEW fraud type

3. **Test Window Expiry:**
   - Set ThrottleWindowHours to 1 (for testing)
   - Generate alert, wait 61 minutes
   - Generate same fraud type
   - Verify alert sent (window expired)

---

## Support

For issues or questions:
- Review logs for throttling decisions
- Check AlertHistory table in ClickHouse
- Verify ThrottleWindowHours configuration
- Ensure AlertHistoryService is registered in DI

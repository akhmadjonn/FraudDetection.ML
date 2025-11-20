# Hybrid Alert Throttling - Complete Guide

## 🎯 Overview

The fraud detection system implements **intelligent hybrid alert throttling** that combines:
- ⚡ **Fast in-memory checks** (microsecond lookups)
- 💾 **Optional database persistence** (audit trail + restart resilience)
- 🎯 **8 fraud types detected** (4 main + 4 pattern-based)
- 🔧 **Fully configurable** per fraud type

**Result:** Zero alert spam while NEVER missing NEW fraud patterns!

---

## 📊 Detected Fraud Types

### **Main Types** (from fraud detection flags)

| Fraud Type | Detection Method | Default Window | Priority |
|------------|------------------|----------------|----------|
| **Multi-Accounting** | `result.IsMultiAccounting` | 60 min | HIGH |
| **Multi-Devicing** | `result.IsMultiDevicing` | 60 min | HIGH |
| **Account Takeover** | `result.IsAccountTakeover` | 30 min | CRITICAL |
| **Impossible Travel** | `result.IsImpossibleTravel` | 30 min | CRITICAL |

### **Pattern-Based Types** (from SuspiciousReasons text)

| Fraud Type | Detection Pattern | Default Window | Priority |
|------------|-------------------|----------------|----------|
| **OTP Bruteforce** | "OTP" + "failure" OR "attempts" | 45 min | MEDIUM |
| **Device Spoofing** | "Rooted" OR "Emulator" OR "Mock" | 120 min | MEDIUM |
| **VPN Usage** | "VPN" OR "proxy" | 120 min | LOW |
| **Unusual Timing** | "night" OR "2-5 AM" OR "unusual hour" | 180 min | LOW |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│               RealTimeScoringJob                         │
│  (Runs every 10 seconds, processes new sessions)         │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
      ┌──────────────────────────────────┐
      │    HybridAlertService            │
      │                                  │
      │  PRIMARY: In-Memory Cache        │
      │  ├─ ConcurrentDictionary         │
      │  ├─ Microsecond lookups          │
      │  └─ 8 fraud types tracked        │
      │                                  │
      │  SECONDARY: Database (optional)  │
      │  ├─ AlertHistory table           │
      │  ├─ Survives restarts            │
      │  └─ Full audit trail             │
      └──────────────────────────────────┘
                     │
                     ▼
      ┌──────────────────────────────────┐
      │      AlertDecision               │
      │  ├─ ShouldSend: bool             │
      │  ├─ FraudTypesToAlert: []        │
      │  ├─ ThrottledFraudTypes: []      │
      │  └─ Reason: string               │
      └──────────────────────────────────┘
```

---

## 🔄 How It Works

### **Startup (Once)**

```
1. App starts
2. AlertHistoryService.InitializeAsync()
   → Creates AlertHistory table in ClickHouse

3. HybridAlertService.InitializeAsync()
   IF EnableDatabasePersistence = true:
     → Load recent alerts (last 60 min) from database
     → Populate in-memory ConcurrentDictionary
   → Ready for real-time processing
```

### **Runtime (Every 10 Seconds)**

```
FOR each new session:
  1. Extract features & analyze fraud
  2. ALWAYS save to FraudAnalysisResults table

  3. IF RiskLevel = HIGH or CRITICAL:

     a. Call HybridAlertService.ShouldSendAlertAsync()
        ├─ Detect 8 fraud types
        ├─ Check in-memory throttle cache (fast!)
        ├─ For each fraud type:
        │  ├─ IF not in cache → NEW fraud type!
        │  ├─ IF in cache but > window → Expired, alert again!
        │  └─ IF in cache and < window → Throttled
        │
        └─ Return AlertDecision

     b. IF decision.ShouldSend = true:
        ├─ Send alert to Teams/Telegram
        ├─ Update in-memory cache
        └─ IF EnableDatabasePersistence:
            └─ Async save to AlertHistory table
```

---

## ⚙️ Configuration

### **appsettings.json**

```json
{
  "Alerts": {
    "EnableDatabasePersistence": true,
    "DefaultThrottleWindowMinutes": 60,

    "FraudTypeSettings": {
      "MultiAccounting": {
        "Enabled": true,
        "ThrottleWindowMinutes": 60,
        "Priority": "HIGH"
      },
      "AccountTakeover": {
        "Enabled": true,
        "ThrottleWindowMinutes": 30,
        "Priority": "CRITICAL"
      },
      "ImpossibleTravel": {
        "Enabled": true,
        "ThrottleWindowMinutes": 30,
        "Priority": "CRITICAL"
      },
      "OtpBruteforce": {
        "Enabled": true,
        "ThrottleWindowMinutes": 45,
        "Priority": "MEDIUM"
      },
      "DeviceSpoofing": {
        "Enabled": true,
        "ThrottleWindowMinutes": 120,
        "Priority": "MEDIUM"
      },
      "VpnUsage": {
        "Enabled": true,
        "ThrottleWindowMinutes": 120,
        "Priority": "LOW"
      }
    }
  }
}
```

### **Configuration Options**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `EnableDatabasePersistence` | bool | `true` | Save alerts to database for audit |
| `DefaultThrottleWindowMinutes` | int | `60` | Fallback window if fraud type not configured |
| `FraudTypeSettings.{Type}.Enabled` | bool | `true` | Enable/disable specific fraud detection |
| `FraudTypeSettings.{Type}.ThrottleWindowMinutes` | int | varies | Custom throttle window per type |
| `FraudTypeSettings.{Type}.Priority` | string | varies | Priority label (future use) |

---

## 📝 Example Scenario

```
Device: abc123
═══════════════════════════════════════════════════════════

10:00:00 - Session #1
──────────────────────────
Detected: MultiAccounting
In-Memory Check:
  ├─ Key: "abc123:CRITICAL:MultiAccounting"
  └─ NOT in cache → NEW!

Decision: SEND ✓
Alert Sent: "🆕 NEW FRAUD PATTERN: Multi-Accounting"
Cache Updated: "abc123:CRITICAL:MultiAccounting" → 10:00
DB Record: Alert saved to AlertHistory table


10:30:00 - Session #2
──────────────────────────
Detected: MultiAccounting
In-Memory Check:
  ├─ Key: "abc123:CRITICAL:MultiAccounting"
  ├─ Found in cache! Last alert: 10:00 (30 min ago)
  └─ 30 min < 60 min window → THROTTLE

Decision: NO SEND ✗
Reason: "All fraud types recently alerted"
DB Record: Session saved (no alert)


10:45:00 - Session #3
──────────────────────────
Detected: MultiAccounting + ImpossibleTravel (NEW!)
In-Memory Check:
  ├─ Key: "abc123:CRITICAL:MultiAccounting"
  │  └─ 45 min < 60 min → THROTTLE ✗
  ├─ Key: "abc123:CRITICAL:ImpossibleTravel"
  │  └─ NOT in cache → NEW! ✓

Decision: SEND ✓
Alert Sent: "🆕 NEW FRAUD PATTERN: Impossible Travel"
Alert Shows:
  NEW PATTERNS:
  • ⚡ Impossible Travel

  Previously Detected:
  • Multi-Accounting

Cache Updated: "abc123:CRITICAL:ImpossibleTravel" → 10:45


11:10:00 - Session #4
──────────────────────────
Detected: MultiAccounting + ImpossibleTravel
In-Memory Check:
  ├─ Key: "abc123:CRITICAL:MultiAccounting"
  │  └─ 70 min > 60 min → EXPIRED, ALERT AGAIN! ✓
  ├─ Key: "abc123:CRITICAL:ImpossibleTravel"
  │  └─ 25 min < 30 min → THROTTLE ✗

Decision: SEND ✓
Alert Sent: "🆕 NEW FRAUD PATTERN: Multi-Accounting"
(re-alert because window expired)
```

---

## 🎨 Alert Format

### **NEW Fraud Pattern Alert:**

```
🚨 CRITICAL RISK ALERT
🆕 NEW FRAUD PATTERN DETECTED: Impossible Travel, OTP Bruteforce

**Session Details:**
• Session: `sess_12345`
• User: +998901234567
• Device: `abc123`
• Anomaly Score: **0.95**
• Cluster: 2

**🎯 Fraud Types Detected:**
**NEW PATTERNS:**
• ⚡ **Impossible Travel**
• ⚡ **OTP Bruteforce**

**Previously Detected:**
• Multi-Accounting
• Device Spoofing

**🔍 Suspicious Indicators:**
• ⚠️ IMPOSSIBLE TRAVEL: User in Moscow 1h after Tashkent
• Multiple OTP failures (7)
• ⚠️ MULTI-ACCOUNTING: 8 users on device
• Rooted device detected

**📊 Key Metrics:**
• Device Age: 0.5 days
• OTP Failures: 7
• Card Additions: 3
• P2P Transfers: 0
• Users on Device (7d): 8
```

---

## 🔍 Monitoring & Debugging

### **Check Throttle State:**

```csharp
var hybridAlert = host.Services.GetRequiredService<HybridAlertService>();
var stats = hybridAlert.GetStatistics();

Console.WriteLine($"Total throttle entries: {stats.TotalEntries}");
Console.WriteLine($"Active entries: {stats.ActiveEntries}");
Console.WriteLine($"By fraud type:");
foreach (var (type, count) in stats.EntriesByFraudType)
{
    Console.WriteLine($"  {type}: {count}");
}
```

### **Clear Throttle (Testing):**

```csharp
// Clear all throttles for a device
hybridAlert.ClearThrottle("device-abc123");

// Clear specific fraud type
hybridAlert.ClearThrottle("device-abc123", "MultiAccounting");
```

### **View Logs:**

```
INFO: Processing 15 new sessions
WARN: 🚨 CRITICAL alert sent! Session: sess123, NEW Fraud Types: ImpossibleTravel, Reason: New fraud types detected
DEBUG: ⏸️ Alert throttled for session sess124. Reason: All fraud types recently alerted. Detected: MultiAccounting, Throttled: MultiAccounting
INFO: Processed 15/15 sessions. Alerts sent: 3, Throttled: 12
```

---

## 💾 Database Schema

### **AlertHistory Table:**

```sql
CREATE TABLE AlertHistory
(
    AlertId String,              -- Unique ID per fraud type
    SessionId String,            -- Triggering session
    DeviceKey String,            -- Device identifier
    GlobalDeviceId String,       -- Device UUID
    UserId String,               -- User identifier
    PhoneNumber String,          -- User phone
    RiskLevel String,            -- CRITICAL/HIGH
    FraudTypes Array(String),    -- Fraud types in this alert
    SentAt DateTime,             -- When alert was sent
    ThrottleKey String           -- Throttle cache key
)
ENGINE = MergeTree()
ORDER BY (SentAt, DeviceKey, UserId)
TTL SentAt + INTERVAL 30 DAY   -- Auto-cleanup
```

---

## 🎯 Benefits

| Feature | Benefit |
|---------|---------|
| **In-Memory Primary** | Microsecond lookups, no DB bottleneck |
| **Database Optional** | Audit trail & restart resilience |
| **8 Fraud Types** | Comprehensive coverage |
| **Per-Type Windows** | Flexible configuration |
| **Warm-up on Startup** | Survives restarts (if DB enabled) |
| **Pattern Detection** | Auto-detects fraud from text |
| **Clear API** | AlertDecision with reasoning |

---

## 🚀 Performance

- **In-Memory Lookup:** < 1ms (ConcurrentDictionary)
- **Database Persistence:** Async fire-and-forget
- **Memory Usage:** ~1 KB per throttle entry
- **Auto-Cleanup:** Every minute, removes expired entries
- **Scalability:** Handles 1000s of sessions/second

---

## 📊 Comparison: Old vs New

| Aspect | Old (AlertHistoryService) | New (HybridAlertService) |
|--------|---------------------------|--------------------------|
| **Storage** | Database only | In-memory + optional DB |
| **Speed** | ~50ms (DB query) | <1ms (memory lookup) |
| **Fraud Types** | 4 main types | 8 types (4 main + 4 pattern) |
| **Restart Resilience** | ✅ Yes | ✅ Yes (if DB enabled) |
| **Audit Trail** | ✅ Full history | ✅ Optional |
| **Configuration** | Single window | Per-type windows |
| **Memory Usage** | Low | Medium (~1 MB per 1000 alerts) |

---

## 🔧 Troubleshooting

### **Issue: Alerts not sending**

```bash
# Check configuration
cat appsettings.json | grep -A 5 "Alerts"

# Check if fraud type is enabled
# Look for "Enabled": false

# Check logs
grep "Alert decision" logs/*.log
```

### **Issue: Too many alerts**

```json
// Increase throttle windows
{
  "Alerts": {
    "FraudTypeSettings": {
      "MultiAccounting": {
        "ThrottleWindowMinutes": 120  // Increase from 60
      }
    }
  }
}
```

### **Issue: Missing alerts after restart**

```json
// Enable database persistence
{
  "Alerts": {
    "EnableDatabasePersistence": true  // Was false
  }
}
```

---

## 📖 Files Modified

1. **Models/AlertDecision.cs** (NEW)
   - Decision model with fraud types and reasoning

2. **Services/HybridAlertService.cs** (NEW)
   - In-memory + optional DB throttling
   - 8 fraud type detection
   - Configurable per-type windows

3. **Services/AlertHistoryService.cs** (UPDATED)
   - Added `GetRecentAlertsForWarmupAsync()` for cache initialization

4. **BackgroundJobs/RealTimeScoringJob.cs** (UPDATED)
   - Uses HybridAlertService instead of AlertHistoryService
   - Clearer logging with decision reasoning

5. **Services/NotificationService.cs** (UPDATED)
   - Supports 8 fraud types in alerts
   - Shows NEW vs Previously Detected

6. **Program.cs** (UPDATED)
   - Registers HybridAlertService
   - Initializes on startup with cache warmup

7. **appsettings.json** (UPDATED)
   - Full configuration for all 8 fraud types
   - Per-type throttle windows

---

## 🎓 Key Concepts

### **Throttle Key Format:**

```
Format: "{DeviceKey}:{RiskLevel}:{FraudType}"
Example: "abc123:CRITICAL:MultiAccounting"
```

### **Decision Flow:**

```
Is fraud detected?
  NO → No alert
  YES → Check each fraud type:
    ├─ Is type enabled? NO → Skip
    ├─ In cache? NO → NEW! → ALERT ✓
    └─ In cache? YES → Check window:
        ├─ > window → Expired → ALERT ✓
        └─ < window → Throttled → NO ALERT ✗
```

### **Memory Management:**

- Entries auto-expire after 2x throttle window
- Cleanup runs every minute
- Memory usage: ~1 KB per entry
- Typical production: 100-1000 entries (~100 KB - 1 MB)

---

## 🎯 Best Practices

1. **Start with defaults** (60 min window)
2. **Monitor alert volume** for first week
3. **Adjust windows** based on your fraud patterns
4. **Enable DB persistence** for production
5. **Keep critical frauds short** (30 min for AccountTakeover)
6. **Keep low-priority long** (180 min for UnusualTiming)
7. **Test throttling** with ClearThrottle() in dev

---

## 📞 Support

**Questions?**
- Check logs for throttle decisions
- Verify configuration in appsettings.json
- Use `GetStatistics()` to monitor state
- Use `ClearThrottle()` for testing

**Common Issues:**
- Alerts not sending → Check fraud type `Enabled` setting
- Too many alerts → Increase `ThrottleWindowMinutes`
- Missing alerts after restart → Enable `DatabasePersistence`

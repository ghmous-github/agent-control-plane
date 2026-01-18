# Production Touch Tracking with Risk Categorization

## Overview

The Agent Control Plane now includes comprehensive production touch tracking that captures **every action** with detailed risk assessment across four critical dimensions: **Security**, **Privacy**, **Reliability**, and **Compliance**.

This feature solves a critical challenge: **capturing every production touch, with every type of security/privacy/reliability risk**.

## Key Features

### 1. Multi-Dimensional Risk Assessment

Every agent action is automatically assessed across four risk categories:

- **Security Risk** (0.0-1.0): Authentication, authorization, injection attacks, credential exposure
- **Privacy Risk** (0.0-1.0): PII exposure, data leakage, GDPR compliance
- **Reliability Risk** (0.0-1.0): System stability, data integrity, availability
- **Compliance Risk** (0.0-1.0): Regulatory requirements, audit trails, governed data

### 2. Environment-Aware Tracking

Actions are categorized by environment:

- `PRODUCTION` - Live production systems
- `STAGING` - Pre-production staging
- `DEVELOPMENT` - Development environments
- `TESTING` - Test environments
- `SHADOW` - Shadow mode execution

Production touches automatically receive elevated risk scores.

### 3. Comprehensive Audit Trail

The FlightRecorder (SQLite-based) captures:

- All risk scores by category
- Environment type and production touch flag
- Specific risk factors identified
- Complete parameters and context
- Timestamps and agent identifiers

### 4. Pattern Detection

Automatic detection of risky patterns:

- SQL injection attempts (`DROP TABLE`, `DELETE FROM`, etc.)
- Credential exposure (`password`, `api_key`, `token`)
- PII indicators (`ssn`, `email`, `credit_card`)
- Destructive operations (`delete`, `drop`, `truncate`)
- Regulated data (`medical`, `financial`, `HIPAA`)

## Usage

### Basic Example

```python
from agent_control_plane import (
    AgentControlPlane,
    AgentContext,
    ActionType,
    PermissionLevel,
    EnvironmentType,
    RiskCategory,
    FlightRecorder,
)
from datetime import datetime

# Initialize
control_plane = AgentControlPlane(enable_default_policies=True)
flight_recorder = FlightRecorder(db_path="production_audit.db")

# Create a production agent
prod_agent = AgentContext(
    agent_id="prod-agent-001",
    session_id="session-001",
    created_at=datetime.now(),
    permissions={
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
    },
    environment=EnvironmentType.PRODUCTION,  # Production environment!
)

# Execute an action
request = control_plane.kernel.submit_request(
    prod_agent,
    ActionType.DATABASE_QUERY,
    {"query": "SELECT email, ssn FROM users WHERE id = 123"}
)

# Risk is automatically assessed
print(f"Is Production Touch: {request.is_production_touch}")  # True
print(f"Overall Risk: {request.risk_score:.2f}")  # e.g., 0.64

# Access detailed risk breakdown
if request.risk_details:
    print(f"Security Risk:    {request.risk_details.security_risk:.2f}")
    print(f"Privacy Risk:     {request.risk_details.privacy_risk:.2f}")
    print(f"Reliability Risk: {request.risk_details.reliability_risk:.2f}")
    print(f"Compliance Risk:  {request.risk_details.compliance_risk:.2f}")
    print(f"Risk Factors: {request.risk_details.risk_factors}")
```

### Logging to FlightRecorder

```python
# Start a trace
trace_id = flight_recorder.start_trace(
    agent_id=request.agent_context.agent_id,
    tool_name=request.action_type.value,
    tool_args=request.parameters,
)

# Log risk details
flight_recorder.log_risk_details(
    trace_id=trace_id,
    is_production_touch=request.is_production_touch,
    environment=request.agent_context.environment.value,
    security_risk=request.risk_details.security_risk,
    privacy_risk=request.risk_details.privacy_risk,
    reliability_risk=request.risk_details.reliability_risk,
    compliance_risk=request.risk_details.compliance_risk,
    overall_risk=request.risk_score,
    risk_factors=request.risk_details.risk_factors,
)

# Log outcome
flight_recorder.log_success(trace_id)
```

### Querying Production Touches

```python
# Get all production touches
prod_touches = flight_recorder.query_production_touches()

# Filter by risk level
high_risk_prod = flight_recorder.query_production_touches(min_risk=0.7)

# Filter by agent
agent_prod = flight_recorder.query_production_touches(agent_id="prod-agent-001")

# With time range
from datetime import datetime, timedelta
recent_prod = flight_recorder.query_production_touches(
    start_time=datetime.now() - timedelta(hours=24)
)
```

### Querying by Risk Category

```python
# High security risk actions
high_security = flight_recorder.query_by_risk_category(
    "security", 
    min_risk=0.7
)

# High privacy risk actions
high_privacy = flight_recorder.query_by_risk_category(
    "privacy", 
    min_risk=0.6
)

# High compliance risk
high_compliance = flight_recorder.query_by_risk_category(
    "compliance",
    min_risk=0.5
)
```

### Getting Risk Summaries

```python
# Comprehensive risk summary
summary = flight_recorder.get_risk_summary()

print(f"High-risk actions: {summary['high_risk_actions']}")
print(f"By environment: {summary['by_environment']}")
print(f"Top risk factors: {summary['top_risk_factors']}")
print(f"High risk by category: {summary['high_risk_by_category']}")

# Overall statistics
stats = flight_recorder.get_statistics()

print(f"Total actions: {stats['total_actions']}")
print(f"Production touches: {stats['production_touches']}")
print(f"Average overall risk: {stats['risk_statistics']['avg_overall_risk']:.2f}")
```

## Risk Assessment Logic

### Security Risk

**Base weights by action type:**
- CODE_EXECUTION: 0.9 (highest)
- DATABASE_WRITE: 0.7
- FILE_WRITE: 0.6
- API_CALL: 0.5
- DATABASE_QUERY: 0.3
- FILE_READ: 0.2

**Elevated by patterns:**
- SQL injection patterns (+0.3): `DROP TABLE`, `DELETE FROM`, `UNION SELECT`, `exec()`
- Credential exposure (+0.2): `password`, `api_key`, `secret`, `token`

### Privacy Risk

**Base weights by action type:**
- API_CALL: 0.7 (may transmit PII)
- DATABASE_WRITE: 0.6 (may store PII)
- DATABASE_QUERY: 0.5 (may access PII)
- CODE_EXECUTION: 0.5
- FILE_WRITE: 0.4
- FILE_READ: 0.3

**Elevated by patterns:**
- PII indicators (+0.3): `ssn`, `email`, `phone`, `credit_card`, `passport`
- GDPR keywords (+0.15): `personal_data`, `user_data`, `customer`

### Reliability Risk

**Base weights by action type:**
- CODE_EXECUTION: 0.8 (system stability)
- DATABASE_WRITE: 0.7 (data integrity)
- FILE_WRITE: 0.6
- WORKFLOW_TRIGGER: 0.5
- API_CALL: 0.4
- DATABASE_QUERY: 0.3
- FILE_READ: 0.2

**Elevated by patterns:**
- Destructive operations (+0.3): `delete`, `drop`, `truncate`, `destroy`
- Batch operations (+0.2): `batch`, `bulk`, `mass`

### Compliance Risk

**Base weights by action type:**
- CODE_EXECUTION: 0.7 (must be logged)
- DATABASE_WRITE: 0.6 (modification tracking)
- FILE_WRITE: 0.5
- WORKFLOW_TRIGGER: 0.5
- API_CALL: 0.4
- DATABASE_QUERY: 0.3
- FILE_READ: 0.2

**Elevated by:**
- Production environment (+0.2)
- Regulated data keywords (+0.25): `financial`, `medical`, `HIPAA`, `SOX`, `PCI`

### Overall Risk

Weighted average: `Security * 0.3 + Privacy * 0.3 + Reliability * 0.2 + Compliance * 0.2`

Production touches receive a 1.2x multiplier (capped at 1.0).

## Database Schema

The FlightRecorder extends the audit log table with risk tracking fields:

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_args TEXT,
    input_prompt TEXT,
    policy_verdict TEXT NOT NULL,
    violation_reason TEXT,
    result TEXT,
    execution_time_ms REAL,
    metadata TEXT,
    
    -- New risk tracking fields
    is_production_touch INTEGER DEFAULT 0,
    environment TEXT,
    security_risk REAL DEFAULT 0.0,
    privacy_risk REAL DEFAULT 0.0,
    reliability_risk REAL DEFAULT 0.0,
    compliance_risk REAL DEFAULT 0.0,
    overall_risk REAL DEFAULT 0.0,
    risk_factors TEXT  -- JSON array
);
```

## API Reference

### New Enums

```python
class RiskCategory(Enum):
    SECURITY = "security"
    PRIVACY = "privacy"
    RELIABILITY = "reliability"
    COMPLIANCE = "compliance"

class EnvironmentType(Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    SHADOW = "shadow"
```

### New Dataclasses

```python
@dataclass
class RiskDetails:
    security_risk: float = 0.0
    privacy_risk: float = 0.0
    reliability_risk: float = 0.0
    compliance_risk: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    @property
    def overall_risk(self) -> float:
        """Weighted average of all risk categories"""
    
    def get_risk_by_category(self, category: RiskCategory) -> float:
        """Get risk score for specific category"""
```

### Extended Classes

```python
@dataclass
class AgentContext:
    # ... existing fields ...
    environment: EnvironmentType = EnvironmentType.DEVELOPMENT

@dataclass
class ExecutionRequest:
    # ... existing fields ...
    risk_details: Optional[RiskDetails] = None
    is_production_touch: bool = False
```

### FlightRecorder Methods

```python
# New methods
def log_risk_details(
    trace_id: str,
    is_production_touch: bool,
    environment: str,
    security_risk: float,
    privacy_risk: float,
    reliability_risk: float,
    compliance_risk: float,
    overall_risk: float,
    risk_factors: Optional[List[str]],
)

def query_production_touches(
    agent_id: Optional[str] = None,
    min_risk: Optional[float] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100,
) -> list

def query_by_risk_category(
    risk_category: str,
    min_risk: float = 0.5,
    limit: int = 100,
) -> list

def get_risk_summary() -> Dict[str, Any]
```

## Use Cases

### 1. Compliance Auditing

Track all production touches with PII for GDPR/HIPAA compliance:

```python
# Find all high-privacy risk production touches
high_privacy = flight_recorder.query_production_touches(min_risk=0.6)

# Filter for PII-related actions
pii_actions = [
    action for action in high_privacy 
    if action['privacy_risk'] > 0.7
]

# Generate compliance report
for action in pii_actions:
    print(f"Agent: {action['agent_id']}")
    print(f"Action: {action['tool_name']}")
    print(f"Time: {action['timestamp']}")
    print(f"Privacy Risk: {action['privacy_risk']:.2f}")
```

### 2. Security Incident Response

Investigate potential security breaches:

```python
# Find all high-security risk actions in last 24 hours
from datetime import datetime, timedelta

recent_threats = flight_recorder.query_by_risk_category(
    "security",
    min_risk=0.8
)

# Analyze risk factors
summary = flight_recorder.get_risk_summary()
print("Top attack patterns:", summary['top_risk_factors'])
```

### 3. Production Change Control

Review all production modifications:

```python
# Get all production database writes
prod_writes = flight_recorder.query_production_touches()
db_writes = [
    w for w in prod_writes 
    if 'database_write' in w['tool_name']
]

# Check for high-reliability risk
risky_changes = [
    w for w in db_writes 
    if w['reliability_risk'] > 0.6
]
```

### 4. Risk-Based Alerting

Set up automated alerts:

```python
# Monitor for high-risk production touches
prod_touches = flight_recorder.query_production_touches(min_risk=0.8)

for touch in prod_touches:
    if touch['overall_risk'] > 0.8:
        send_alert(
            f"HIGH RISK PRODUCTION ACTION: "
            f"{touch['agent_id']} - {touch['tool_name']} "
            f"(Risk: {touch['overall_risk']:.2f})"
        )
```

## Best Practices

1. **Always specify environment**: Set the correct `EnvironmentType` for each agent context
2. **Monitor production touches**: Regularly review `query_production_touches()` results
3. **Set up alerts**: Configure notifications for high-risk production actions (>0.7)
4. **Regular audits**: Use `get_risk_summary()` for periodic security reviews
5. **Investigate patterns**: Check `top_risk_factors` to identify common vulnerabilities
6. **Archive logs**: Implement log rotation and archival for long-term compliance

## Examples

See the complete working example in `examples/production_touch_tracking.py`.

Run it with:

```bash
python examples/production_touch_tracking.py
```

This demonstrates:
- Environment-aware agent creation
- Risk assessment across all categories
- Production vs development risk differences
- FlightRecorder logging and querying
- Comprehensive risk analysis

## Migration Guide

Existing code continues to work without changes. To adopt risk tracking:

1. **Add environment to agent contexts**:
   ```python
   context = AgentContext(
       # ... existing fields ...
       environment=EnvironmentType.PRODUCTION,  # Add this
   )
   ```

2. **Use risk details**:
   ```python
   request = kernel.submit_request(...)
   if request.risk_details:
       print(f"Security: {request.risk_details.security_risk}")
   ```

3. **Log to FlightRecorder**:
   ```python
   flight_recorder.log_risk_details(
       trace_id=trace_id,
       is_production_touch=request.is_production_touch,
       # ... risk fields ...
   )
   ```

## Performance Considerations

- Risk assessment adds minimal overhead (<1ms per request)
- SQLite database handles 10,000+ inserts/second
- Indexes on production_touch, environment, and risk scores for fast queries
- Use `limit` parameter in queries to control memory usage

## Future Enhancements

- Machine learning-based risk prediction
- Custom risk weighting profiles
- Real-time risk dashboards
- Integration with SIEM systems
- Automated risk-based policy adjustments

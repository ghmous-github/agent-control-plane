"""
Production Touch Tracking with Risk Categorization - Complete Example

This example demonstrates the comprehensive production touch tracking system
that captures every action with detailed security/privacy/reliability/compliance
risk assessment.
"""

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


def main():
    print("=" * 80)
    print("Production Touch Tracking with Risk Categorization Demo")
    print("=" * 80)
    print()

    # -------------------------------------------------------------------------
    # 1. Initialize Control Plane with Flight Recorder
    # -------------------------------------------------------------------------
    print("1. Setting up Control Plane with Flight Recorder...")
    
    control_plane = AgentControlPlane(enable_default_policies=True)
    flight_recorder = FlightRecorder(db_path="production_audit.db")
    
    print("✓ Control Plane initialized")
    print("✓ Flight Recorder initialized")
    print()

    # -------------------------------------------------------------------------
    # 2. Create agents in different environments
    # -------------------------------------------------------------------------
    print("2. Creating agents in different environments...")
    
    # Development agent
    dev_agent = AgentContext(
        agent_id="dev-agent-001",
        session_id="dev-session-001",
        created_at=datetime.now(),
        permissions={
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.FILE_WRITE: PermissionLevel.READ_WRITE,
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        },
        environment=EnvironmentType.DEVELOPMENT,
    )
    
    # Production agent
    prod_agent = AgentContext(
        agent_id="prod-agent-001",
        session_id="prod-session-001",
        created_at=datetime.now(),
        permissions={
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
            ActionType.API_CALL: PermissionLevel.READ_WRITE,
        },
        environment=EnvironmentType.PRODUCTION,
    )
    
    print(f"✓ Development agent created: {dev_agent.agent_id}")
    print(f"✓ Production agent created: {prod_agent.agent_id}")
    print()

    # -------------------------------------------------------------------------
    # 3. Execute actions and demonstrate risk categorization
    # -------------------------------------------------------------------------
    print("3. Executing actions with risk assessment...")
    print()

    # Example 1: Low-risk development action
    print("Example 1: Development - Simple File Read")
    print("-" * 60)
    dev_request_1 = control_plane.kernel.submit_request(
        dev_agent,
        ActionType.FILE_READ,
        {"path": "/tmp/test.txt"}
    )
    
    print(f"Environment: {dev_agent.environment.value}")
    print(f"Is Production Touch: {dev_request_1.is_production_touch}")
    print(f"Overall Risk Score: {dev_request_1.risk_score:.2f}")
    if dev_request_1.risk_details:
        print(f"  └─ Security Risk:    {dev_request_1.risk_details.security_risk:.2f}")
        print(f"  └─ Privacy Risk:     {dev_request_1.risk_details.privacy_risk:.2f}")
        print(f"  └─ Reliability Risk: {dev_request_1.risk_details.reliability_risk:.2f}")
        print(f"  └─ Compliance Risk:  {dev_request_1.risk_details.compliance_risk:.2f}")
    print()

    # Example 2: High-risk production action with PII
    print("Example 2: Production - Database Query with PII")
    print("-" * 60)
    prod_request_1 = control_plane.kernel.submit_request(
        prod_agent,
        ActionType.DATABASE_QUERY,
        {"query": "SELECT email, ssn, phone FROM users WHERE customer_id = 123"}
    )
    
    print(f"Environment: {prod_agent.environment.value}")
    print(f"Is Production Touch: {prod_request_1.is_production_touch}")
    print(f"Overall Risk Score: {prod_request_1.risk_score:.2f}")
    if prod_request_1.risk_details:
        print(f"  └─ Security Risk:    {prod_request_1.risk_details.security_risk:.2f}")
        print(f"  └─ Privacy Risk:     {prod_request_1.risk_details.privacy_risk:.2f}")
        print(f"  └─ Reliability Risk: {prod_request_1.risk_details.reliability_risk:.2f}")
        print(f"  └─ Compliance Risk:  {prod_request_1.risk_details.compliance_risk:.2f}")
        print(f"Risk Factors: {prod_request_1.risk_details.risk_factors}")
    print()

    # Example 3: Dangerous operation (blocked by default policies)
    print("Example 3: Development - SQL Injection Attempt")
    print("-" * 60)
    dev_request_2 = control_plane.kernel.submit_request(
        dev_agent,
        ActionType.DATABASE_QUERY,
        {"query": "SELECT * FROM users; DROP TABLE users;--"}
    )
    
    print(f"Environment: {dev_agent.environment.value}")
    print(f"Request Status: {dev_request_2.status.value}")
    print(f"Overall Risk Score: {dev_request_2.risk_score:.2f}")
    if dev_request_2.risk_details:
        print(f"  └─ Security Risk:    {dev_request_2.risk_details.security_risk:.2f}")
        print(f"  └─ Privacy Risk:     {dev_request_2.risk_details.privacy_risk:.2f}")
        print(f"  └─ Reliability Risk: {dev_request_2.risk_details.reliability_risk:.2f}")
        print(f"  └─ Compliance Risk:  {dev_request_2.risk_details.compliance_risk:.2f}")
        print(f"Risk Factors: {dev_request_2.risk_details.risk_factors}")
    print()

    # Example 4: Production API call with credentials
    print("Example 4: Production - API Call with Potential Credential Exposure")
    print("-" * 60)
    prod_request_2 = control_plane.kernel.submit_request(
        prod_agent,
        ActionType.API_CALL,
        {
            "url": "https://api.example.com/process",
            "headers": {"Authorization": "Bearer token123"},
            "payload": {"api_key": "secret123", "user_data": "sensitive"}
        }
    )
    
    print(f"Environment: {prod_agent.environment.value}")
    print(f"Is Production Touch: {prod_request_2.is_production_touch}")
    print(f"Overall Risk Score: {prod_request_2.risk_score:.2f}")
    if prod_request_2.risk_details:
        print(f"  └─ Security Risk:    {prod_request_2.risk_details.security_risk:.2f}")
        print(f"  └─ Privacy Risk:     {prod_request_2.risk_details.privacy_risk:.2f}")
        print(f"  └─ Reliability Risk: {prod_request_2.risk_details.reliability_risk:.2f}")
        print(f"  └─ Compliance Risk:  {prod_request_2.risk_details.compliance_risk:.2f}")
        print(f"Risk Factors: {prod_request_2.risk_details.risk_factors}")
    print()

    # -------------------------------------------------------------------------
    # 4. Log all actions to FlightRecorder
    # -------------------------------------------------------------------------
    print("4. Logging actions to FlightRecorder...")
    print()

    requests = [dev_request_1, prod_request_1, dev_request_2, prod_request_2]
    
    for req in requests:
        trace_id = flight_recorder.start_trace(
            agent_id=req.agent_context.agent_id,
            tool_name=req.action_type.value,
            tool_args=req.parameters,
        )
        
        if req.risk_details:
            flight_recorder.log_risk_details(
                trace_id=trace_id,
                is_production_touch=req.is_production_touch,
                environment=req.agent_context.environment.value,
                security_risk=req.risk_details.security_risk,
                privacy_risk=req.risk_details.privacy_risk,
                reliability_risk=req.risk_details.reliability_risk,
                compliance_risk=req.risk_details.compliance_risk,
                overall_risk=req.risk_score,
                risk_factors=req.risk_details.risk_factors,
            )
            
            if req.status.value == "approved":
                flight_recorder.log_success(trace_id)
            else:
                flight_recorder.log_violation(trace_id, f"Request {req.status.value}")
    
    print("✓ All actions logged to FlightRecorder")
    print()

    # -------------------------------------------------------------------------
    # 5. Query production touches
    # -------------------------------------------------------------------------
    print("5. Querying production touches...")
    print("-" * 60)
    
    prod_touches = flight_recorder.query_production_touches()
    print(f"Total production touches: {len(prod_touches)}")
    
    for touch in prod_touches:
        print(f"\n  Agent: {touch['agent_id']}")
        print(f"  Action: {touch['tool_name']}")
        print(f"  Overall Risk: {touch['overall_risk']:.2f}")
        print(f"  Security: {touch['security_risk']:.2f} | Privacy: {touch['privacy_risk']:.2f} | "
              f"Reliability: {touch['reliability_risk']:.2f} | Compliance: {touch['compliance_risk']:.2f}")
    print()

    # -------------------------------------------------------------------------
    # 6. Query high-risk actions by category
    # -------------------------------------------------------------------------
    print("6. Querying high-risk actions by category...")
    print("-" * 60)
    
    categories = ["security", "privacy", "reliability", "compliance"]
    for category in categories:
        high_risk = flight_recorder.query_by_risk_category(category, min_risk=0.5)
        print(f"\nHigh {category.upper()} risk actions: {len(high_risk)}")
        for action in high_risk[:2]:  # Show first 2
            print(f"  └─ {action['agent_id']}: {action['tool_name']} "
                  f"(Risk: {action[f'{category}_risk']:.2f})")
    print()

    # -------------------------------------------------------------------------
    # 7. Get comprehensive risk summary
    # -------------------------------------------------------------------------
    print("7. Getting comprehensive risk summary...")
    print("-" * 60)
    
    summary = flight_recorder.get_risk_summary()
    
    print(f"\nHigh-risk actions (>0.7): {summary['high_risk_actions']}")
    
    print("\nActions by environment:")
    for env, count in summary['by_environment'].items():
        print(f"  └─ {env}: {count}")
    
    print("\nHigh-risk by category (>0.5):")
    for category, count in summary['high_risk_by_category'].items():
        print(f"  └─ {category.capitalize()}: {count}")
    
    if summary['top_risk_factors']:
        print("\nTop risk factors:")
        for factor in summary['top_risk_factors'][:5]:
            print(f"  └─ {factor['factor']}: {factor['count']} occurrences")
    print()

    # -------------------------------------------------------------------------
    # 8. Get overall statistics
    # -------------------------------------------------------------------------
    print("8. Getting overall statistics...")
    print("-" * 60)
    
    stats = flight_recorder.get_statistics()
    
    print(f"\nTotal actions logged: {stats['total_actions']}")
    print(f"Production touches: {stats['production_touches']}")
    
    print("\nBy verdict:")
    for verdict, count in stats['by_verdict'].items():
        print(f"  └─ {verdict}: {count}")
    
    risk_stats = stats['risk_statistics']
    print("\nAverage risk scores:")
    print(f"  └─ Overall:     {risk_stats['avg_overall_risk']:.2f}")
    print(f"  └─ Security:    {risk_stats['avg_security_risk']:.2f}")
    print(f"  └─ Privacy:     {risk_stats['avg_privacy_risk']:.2f}")
    print(f"  └─ Reliability: {risk_stats['avg_reliability_risk']:.2f}")
    print(f"  └─ Compliance:  {risk_stats['avg_compliance_risk']:.2f}")
    print()

    # -------------------------------------------------------------------------
    # 9. Key Benefits Summary
    # -------------------------------------------------------------------------
    print("=" * 80)
    print("KEY BENEFITS OF PRODUCTION TOUCH TRACKING")
    print("=" * 80)
    print()
    print("✓ Every action is categorized by environment (production/staging/dev)")
    print("✓ Four dimensions of risk tracked: Security, Privacy, Reliability, Compliance")
    print("✓ Production touches automatically get elevated risk scores")
    print("✓ Comprehensive audit trail with queryable risk metadata")
    print("✓ Risk assessment happens BEFORE execution (even for denied requests)")
    print("✓ Pattern detection for common security/privacy violations")
    print("✓ Easy querying by environment, risk category, or specific factors")
    print("✓ Complete forensic capability for compliance and incident response")
    print()
    print("Database location: production_audit.db")
    print("Use FlightRecorder query methods to analyze historical data!")
    print()


if __name__ == "__main__":
    main()

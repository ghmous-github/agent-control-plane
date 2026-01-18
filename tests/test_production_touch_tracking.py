"""
Tests for Production Touch Tracking with Risk Categorization

This test suite validates the comprehensive risk tracking and categorization
system for capturing every production touch with security/privacy/reliability
risk assessment.
"""

import unittest
import os
import tempfile
from datetime import datetime

from agent_control_plane import (
    AgentControlPlane,
    AgentContext,
    ActionType,
    PermissionLevel,
    RiskCategory,
    RiskDetails,
    EnvironmentType,
    FlightRecorder,
)


class TestProductionTouchTracking(unittest.TestCase):
    """Test production touch tracking and risk categorization"""

    def setUp(self):
        """Set up test environment"""
        # Create a temporary database for testing
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.flight_recorder = FlightRecorder(db_path=self.db_path)
        
        # Create control plane
        self.control_plane = AgentControlPlane(enable_default_policies=True)
        
    def tearDown(self):
        """Clean up test environment"""
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_risk_details_creation(self):
        """Test RiskDetails dataclass creation and overall_risk calculation"""
        risk = RiskDetails(
            security_risk=0.8,
            privacy_risk=0.6,
            reliability_risk=0.4,
            compliance_risk=0.5,
        )
        
        # Overall risk should be weighted average
        # (0.8*0.3 + 0.6*0.3 + 0.4*0.2 + 0.5*0.2) = 0.24 + 0.18 + 0.08 + 0.10 = 0.60
        self.assertAlmostEqual(risk.overall_risk, 0.60, places=2)

    def test_risk_by_category(self):
        """Test getting risk score by specific category"""
        risk = RiskDetails(
            security_risk=0.9,
            privacy_risk=0.7,
            reliability_risk=0.3,
            compliance_risk=0.4,
        )
        
        self.assertEqual(risk.get_risk_by_category(RiskCategory.SECURITY), 0.9)
        self.assertEqual(risk.get_risk_by_category(RiskCategory.PRIVACY), 0.7)
        self.assertEqual(risk.get_risk_by_category(RiskCategory.RELIABILITY), 0.3)
        self.assertEqual(risk.get_risk_by_category(RiskCategory.COMPLIANCE), 0.4)

    def test_environment_type_enum(self):
        """Test EnvironmentType enum values"""
        self.assertEqual(EnvironmentType.PRODUCTION.value, "production")
        self.assertEqual(EnvironmentType.STAGING.value, "staging")
        self.assertEqual(EnvironmentType.DEVELOPMENT.value, "development")
        self.assertEqual(EnvironmentType.TESTING.value, "testing")
        self.assertEqual(EnvironmentType.SHADOW.value, "shadow")

    def test_agent_context_with_environment(self):
        """Test AgentContext includes environment information"""
        context = AgentContext(
            agent_id="test-agent",
            session_id="session-123",
            created_at=datetime.now(),
            permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            environment=EnvironmentType.PRODUCTION,
        )
        
        self.assertEqual(context.environment, EnvironmentType.PRODUCTION)

    def test_production_touch_flag(self):
        """Test that production touches are flagged correctly"""
        # Create production context
        prod_context = AgentContext(
            agent_id="prod-agent",
            session_id="session-prod",
            created_at=datetime.now(),
            permissions={ActionType.DATABASE_WRITE: PermissionLevel.READ_WRITE},
            environment=EnvironmentType.PRODUCTION,
        )
        
        # Submit a request
        request = self.control_plane.kernel.submit_request(
            prod_context,
            ActionType.DATABASE_WRITE,
            {"query": "UPDATE users SET active=1"}
        )
        
        # Should be flagged as production touch
        self.assertTrue(request.is_production_touch)
        self.assertIsNotNone(request.risk_details)

    def test_security_risk_assessment(self):
        """Test security risk assessment for dangerous operations"""
        context = AgentContext(
            agent_id="test-agent",
            session_id="session-123",
            created_at=datetime.now(),
            permissions={ActionType.DATABASE_WRITE: PermissionLevel.READ_WRITE},
            environment=EnvironmentType.DEVELOPMENT,
        )
        
        # SQL injection attempt
        request = self.control_plane.kernel.submit_request(
            context,
            ActionType.DATABASE_WRITE,
            {"query": "SELECT * FROM users; DROP TABLE users;--"}
        )
        
        self.assertIsNotNone(request.risk_details)
        # Should have elevated security risk due to dangerous pattern
        self.assertGreater(request.risk_details.security_risk, 0.7)
        self.assertIn("security_pattern:drop table", request.risk_details.risk_factors)

    def test_privacy_risk_assessment(self):
        """Test privacy risk assessment for PII operations"""
        context = AgentContext(
            agent_id="test-agent",
            session_id="session-123",
            created_at=datetime.now(),
            permissions={ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY},
            environment=EnvironmentType.DEVELOPMENT,
        )
        
        # Query with PII
        request = self.control_plane.kernel.submit_request(
            context,
            ActionType.DATABASE_QUERY,
            {"query": "SELECT ssn, email FROM users WHERE id=1"}
        )
        
        self.assertIsNotNone(request.risk_details)
        # Should have elevated privacy risk due to PII
        self.assertGreater(request.risk_details.privacy_risk, 0.5)

    def test_reliability_risk_assessment(self):
        """Test reliability risk assessment for destructive operations"""
        context = AgentContext(
            agent_id="test-agent",
            session_id="session-123",
            created_at=datetime.now(),
            permissions={ActionType.DATABASE_WRITE: PermissionLevel.READ_WRITE},
            environment=EnvironmentType.DEVELOPMENT,
        )
        
        # Destructive operation
        request = self.control_plane.kernel.submit_request(
            context,
            ActionType.DATABASE_WRITE,
            {"query": "DELETE FROM transactions WHERE date < '2024-01-01'"}
        )
        
        self.assertIsNotNone(request.risk_details)
        # Should have elevated reliability risk
        self.assertGreater(request.risk_details.reliability_risk, 0.7)

    def test_compliance_risk_assessment(self):
        """Test compliance risk assessment for regulated data"""
        context = AgentContext(
            agent_id="test-agent",
            session_id="session-123",
            created_at=datetime.now(),
            permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            environment=EnvironmentType.PRODUCTION,
        )
        
        # HIPAA-regulated data
        request = self.control_plane.kernel.submit_request(
            context,
            ActionType.FILE_READ,
            {"path": "/data/medical/patient_records.csv"}
        )
        
        self.assertIsNotNone(request.risk_details)
        # Should have compliance risk due to regulated data + production
        self.assertGreater(request.risk_details.compliance_risk, 0.3)

    def test_flight_recorder_risk_logging(self):
        """Test FlightRecorder logs risk details"""
        trace_id = self.flight_recorder.start_trace(
            agent_id="test-agent",
            tool_name="database_query",
            tool_args={"query": "SELECT * FROM users"},
        )
        
        # Log risk details
        self.flight_recorder.log_risk_details(
            trace_id=trace_id,
            is_production_touch=True,
            environment="production",
            security_risk=0.3,
            privacy_risk=0.6,
            reliability_risk=0.2,
            compliance_risk=0.4,
            overall_risk=0.4,
            risk_factors=["pii_indicator:email", "production_environment"],
        )
        
        # Query the logs
        logs = self.flight_recorder.query_logs(agent_id="test-agent", limit=1)
        self.assertEqual(len(logs), 1)
        
        log = logs[0]
        self.assertEqual(log["is_production_touch"], 1)
        self.assertEqual(log["environment"], "production")
        self.assertEqual(log["security_risk"], 0.3)
        self.assertEqual(log["privacy_risk"], 0.6)
        self.assertEqual(log["reliability_risk"], 0.2)
        self.assertEqual(log["compliance_risk"], 0.4)
        self.assertEqual(log["overall_risk"], 0.4)

    def test_query_production_touches(self):
        """Test querying production touches"""
        # Create multiple traces
        for i in range(5):
            trace_id = self.flight_recorder.start_trace(
                agent_id=f"agent-{i}",
                tool_name="api_call",
            )
            self.flight_recorder.log_risk_details(
                trace_id=trace_id,
                is_production_touch=(i < 3),  # First 3 are production
                environment="production" if i < 3 else "development",
                overall_risk=0.5,
            )
        
        # Query only production touches
        prod_touches = self.flight_recorder.query_production_touches()
        self.assertEqual(len(prod_touches), 3)

    def test_query_by_risk_category(self):
        """Test querying by specific risk category"""
        # Create traces with different risk profiles
        for i in range(3):
            trace_id = self.flight_recorder.start_trace(
                agent_id=f"agent-{i}",
                tool_name="database_write",
            )
            self.flight_recorder.log_risk_details(
                trace_id=trace_id,
                security_risk=0.8 if i == 0 else 0.2,
                privacy_risk=0.2,
                overall_risk=0.5,
            )
        
        # Query high security risk
        high_security = self.flight_recorder.query_by_risk_category(
            "security", min_risk=0.7
        )
        self.assertEqual(len(high_security), 1)

    def test_get_risk_summary(self):
        """Test comprehensive risk summary"""
        # Create some test data
        for i in range(5):
            trace_id = self.flight_recorder.start_trace(
                agent_id=f"agent-{i}",
                tool_name="test_action",
            )
            self.flight_recorder.log_risk_details(
                trace_id=trace_id,
                is_production_touch=(i < 2),
                environment="production" if i < 2 else "development",
                security_risk=0.8 if i == 0 else 0.3,
                privacy_risk=0.6,
                reliability_risk=0.4,
                compliance_risk=0.5,
                overall_risk=0.6 if i == 0 else 0.4,
                risk_factors=["test_factor"],
            )
        
        summary = self.flight_recorder.get_risk_summary()
        
        self.assertIn("high_risk_actions", summary)
        self.assertIn("by_environment", summary)
        self.assertIn("top_risk_factors", summary)
        self.assertIn("high_risk_by_category", summary)
        
        # Check environment breakdown
        self.assertEqual(summary["by_environment"]["production"], 2)
        self.assertEqual(summary["by_environment"]["development"], 3)

    def test_statistics_include_risk_data(self):
        """Test that statistics include risk information"""
        # Create test data
        trace_id = self.flight_recorder.start_trace(
            agent_id="test-agent",
            tool_name="test_action",
        )
        self.flight_recorder.log_risk_details(
            trace_id=trace_id,
            is_production_touch=True,
            overall_risk=0.7,
            security_risk=0.8,
            privacy_risk=0.6,
        )
        
        stats = self.flight_recorder.get_statistics()
        
        self.assertIn("production_touches", stats)
        self.assertIn("risk_statistics", stats)
        self.assertEqual(stats["production_touches"], 1)
        
        risk_stats = stats["risk_statistics"]
        self.assertGreater(risk_stats["avg_overall_risk"], 0)
        self.assertGreater(risk_stats["avg_security_risk"], 0)

    def test_production_touch_elevates_risk(self):
        """Test that production environment elevates overall risk"""
        # Development environment
        dev_context = AgentContext(
            agent_id="dev-agent",
            session_id="session-dev",
            created_at=datetime.now(),
            permissions={ActionType.FILE_WRITE: PermissionLevel.READ_WRITE},
            environment=EnvironmentType.DEVELOPMENT,
        )
        
        dev_request = self.control_plane.kernel.submit_request(
            dev_context,
            ActionType.FILE_WRITE,
            {"path": "/tmp/test.txt", "content": "test"}
        )
        
        # Production environment
        prod_context = AgentContext(
            agent_id="prod-agent",
            session_id="session-prod",
            created_at=datetime.now(),
            permissions={ActionType.FILE_WRITE: PermissionLevel.READ_WRITE},
            environment=EnvironmentType.PRODUCTION,
        )
        
        prod_request = self.control_plane.kernel.submit_request(
            prod_context,
            ActionType.FILE_WRITE,
            {"path": "/tmp/test.txt", "content": "test"}
        )
        
        # Production should have higher overall risk
        self.assertGreater(prod_request.risk_score, dev_request.risk_score)
        self.assertTrue(prod_request.is_production_touch)
        self.assertFalse(dev_request.is_production_touch)

    def test_multiple_risk_factors_accumulation(self):
        """Test that multiple risk factors are properly accumulated"""
        context = AgentContext(
            agent_id="test-agent",
            session_id="session-123",
            created_at=datetime.now(),
            permissions={ActionType.CODE_EXECUTION: PermissionLevel.READ_WRITE},
            environment=EnvironmentType.PRODUCTION,
        )
        
        # Request with multiple risk factors
        request = self.control_plane.kernel.submit_request(
            context,
            ActionType.CODE_EXECUTION,
            {
                "code": "import os; os.system('rm -rf /')",
                "context": "Contains password and api_key for production"
            }
        )
        
        self.assertIsNotNone(request.risk_details)
        # Should have multiple risk factors identified
        self.assertGreater(len(request.risk_details.risk_factors), 1)
        # Overall risk should be high
        self.assertGreater(request.risk_score, 0.7)


if __name__ == "__main__":
    unittest.main()

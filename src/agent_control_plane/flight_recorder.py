"""
Flight Recorder - Black Box Audit Logger for Agent Control Plane

This module provides SQLite-based audit logging for all agent actions,
capturing the exact state for forensic analysis and compliance.
"""

import sqlite3
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
from collections import Counter
import json
import logging


class FlightRecorder:
    """
    The Black Box Recorder for AI Agents.

    Logs every action attempt with full context for forensic analysis.
    Similar to an aircraft's flight data recorder, this captures:
    - Timestamp: When the action was attempted
    - AgentID: Which agent attempted it
    - InputPrompt: The original user/agent intent
    - IntendedAction: What the agent tried to do
    - PolicyVerdict: Whether it was allowed or blocked
    - Result: What actually happened
    """

    def __init__(self, db_path: str = "flight_recorder.db"):
        """
        Initialize the Flight Recorder.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.logger = logging.getLogger("FlightRecorder")
        self._init_database()

    def _init_database(self):
        """Initialize the SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create the main audit log table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
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
                is_production_touch INTEGER DEFAULT 0,
                environment TEXT,
                security_risk REAL DEFAULT 0.0,
                privacy_risk REAL DEFAULT 0.0,
                reliability_risk REAL DEFAULT 0.0,
                compliance_risk REAL DEFAULT 0.0,
                overall_risk REAL DEFAULT 0.0,
                risk_factors TEXT
            )
        """
        )

        # Create indexes for common queries
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_agent_id ON audit_log(agent_id)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_policy_verdict ON audit_log(policy_verdict)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_production_touch ON audit_log(is_production_touch)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_environment ON audit_log(environment)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_overall_risk ON audit_log(overall_risk)
        """
        )

        conn.commit()
        conn.close()

        self.logger.info(f"Flight Recorder initialized: {self.db_path}")

    def start_trace(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        input_prompt: Optional[str] = None,
    ) -> str:
        """
        Start a new trace for an agent action.

        Args:
            agent_id: ID of the agent
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            input_prompt: The original user/agent prompt (optional)

        Returns:
            trace_id: Unique identifier for this trace
        """
        trace_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO audit_log 
            (trace_id, timestamp, agent_id, tool_name, tool_args, input_prompt, policy_verdict)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """,
            (
                trace_id,
                timestamp,
                agent_id,
                tool_name,
                json.dumps(tool_args) if tool_args else None,
                input_prompt,
            ),
        )

        conn.commit()
        conn.close()

        return trace_id

    def log_violation(self, trace_id: str, violation_reason: str):
        """
        Log a policy violation for a trace.

        Args:
            trace_id: The trace ID from start_trace
            violation_reason: Why the action was blocked
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE audit_log 
            SET policy_verdict = 'blocked', 
                violation_reason = ?
            WHERE trace_id = ?
        """,
            (violation_reason, trace_id),
        )

        conn.commit()
        conn.close()

        self.logger.warning(f"BLOCKED: {trace_id} - {violation_reason}")

    def log_shadow_exec(self, trace_id: str, simulated_result: Optional[str] = None):
        """
        Log a shadow mode execution (simulated, not real).

        Args:
            trace_id: The trace ID from start_trace
            simulated_result: The simulated result returned to the agent
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE audit_log 
            SET policy_verdict = 'shadow', 
                result = ?
            WHERE trace_id = ?
        """,
            (simulated_result or "Simulated success", trace_id),
        )

        conn.commit()
        conn.close()

        self.logger.info(f"SHADOW: {trace_id}")

    def log_success(
        self, trace_id: str, result: Optional[Any] = None, execution_time_ms: Optional[float] = None
    ):
        """
        Log a successful execution.

        Args:
            trace_id: The trace ID from start_trace
            result: The result of the execution
            execution_time_ms: How long the execution took
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        result_str = (
            json.dumps(result)
            if result and not isinstance(result, str)
            else str(result) if result else None
        )

        cursor.execute(
            """
            UPDATE audit_log 
            SET policy_verdict = 'allowed', 
                result = ?,
                execution_time_ms = ?
            WHERE trace_id = ?
        """,
            (result_str, execution_time_ms, trace_id),
        )

        conn.commit()
        conn.close()

        self.logger.info(f"ALLOWED: {trace_id}")

    def log_error(self, trace_id: str, error: str):
        """
        Log an execution error.

        Args:
            trace_id: The trace ID from start_trace
            error: The error message
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE audit_log 
            SET policy_verdict = 'error', 
                violation_reason = ?
            WHERE trace_id = ?
        """,
            (error, trace_id),
        )

        conn.commit()
        conn.close()

        self.logger.error(f"ERROR: {trace_id} - {error}")

    def log_risk_details(
        self,
        trace_id: str,
        is_production_touch: bool = False,
        environment: str = "development",
        security_risk: float = 0.0,
        privacy_risk: float = 0.0,
        reliability_risk: float = 0.0,
        compliance_risk: float = 0.0,
        overall_risk: float = 0.0,
        risk_factors: Optional[List[str]] = None,
    ):
        """
        Log detailed risk information for a trace.

        Args:
            trace_id: The trace ID from start_trace
            is_production_touch: Whether this action touches production
            environment: Environment type (production, staging, etc.)
            security_risk: Security risk score (0.0-1.0)
            privacy_risk: Privacy risk score (0.0-1.0)
            reliability_risk: Reliability risk score (0.0-1.0)
            compliance_risk: Compliance risk score (0.0-1.0)
            overall_risk: Overall risk score (0.0-1.0)
            risk_factors: List of specific risk factors identified
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        risk_factors_json = json.dumps(risk_factors) if risk_factors else None

        cursor.execute(
            """
            UPDATE audit_log 
            SET is_production_touch = ?,
                environment = ?,
                security_risk = ?,
                privacy_risk = ?,
                reliability_risk = ?,
                compliance_risk = ?,
                overall_risk = ?,
                risk_factors = ?
            WHERE trace_id = ?
        """,
            (
                1 if is_production_touch else 0,
                environment,
                security_risk,
                privacy_risk,
                reliability_risk,
                compliance_risk,
                overall_risk,
                risk_factors_json,
                trace_id,
            ),
        )

        conn.commit()
        conn.close()

        log_msg = f"RISK: {trace_id} - Overall: {overall_risk:.2f}"
        if is_production_touch:
            log_msg += " [PRODUCTION]"
        self.logger.info(log_msg)

    def query_logs(
        self,
        agent_id: Optional[str] = None,
        policy_verdict: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list:
        """
        Query the audit logs with filters.

        Args:
            agent_id: Filter by agent ID
            policy_verdict: Filter by verdict (allowed, blocked, shadow, error)
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of results

        Returns:
            List of audit log entries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if policy_verdict:
            query += " AND policy_verdict = ?"
            params.append(policy_verdict)

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the audit log.

        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total actions
        cursor.execute("SELECT COUNT(*) FROM audit_log")
        total = cursor.fetchone()[0]

        # By verdict
        cursor.execute(
            """
            SELECT policy_verdict, COUNT(*) as count 
            FROM audit_log 
            GROUP BY policy_verdict
        """
        )
        by_verdict = {row[0]: row[1] for row in cursor.fetchall()}

        # By agent
        cursor.execute(
            """
            SELECT agent_id, COUNT(*) as count 
            FROM audit_log 
            GROUP BY agent_id
            ORDER BY count DESC
            LIMIT 10
        """
        )
        top_agents = [{"agent_id": row[0], "count": row[1]} for row in cursor.fetchall()]

        # Average execution time
        cursor.execute(
            """
            SELECT AVG(execution_time_ms) 
            FROM audit_log 
            WHERE execution_time_ms IS NOT NULL
        """
        )
        avg_exec_time = cursor.fetchone()[0]

        # Production touches
        cursor.execute("SELECT COUNT(*) FROM audit_log WHERE is_production_touch = 1")
        production_touches = cursor.fetchone()[0]

        # Risk statistics
        cursor.execute(
            """
            SELECT AVG(overall_risk), MAX(overall_risk), 
                   AVG(security_risk), AVG(privacy_risk),
                   AVG(reliability_risk), AVG(compliance_risk)
            FROM audit_log 
            WHERE overall_risk > 0
        """
        )
        risk_stats = cursor.fetchone()

        conn.close()

        return {
            "total_actions": total,
            "by_verdict": by_verdict,
            "top_agents": top_agents,
            "avg_execution_time_ms": avg_exec_time,
            "production_touches": production_touches,
            "risk_statistics": {
                "avg_overall_risk": risk_stats[0] if risk_stats[0] else 0.0,
                "max_overall_risk": risk_stats[1] if risk_stats[1] else 0.0,
                "avg_security_risk": risk_stats[2] if risk_stats[2] else 0.0,
                "avg_privacy_risk": risk_stats[3] if risk_stats[3] else 0.0,
                "avg_reliability_risk": risk_stats[4] if risk_stats[4] else 0.0,
                "avg_compliance_risk": risk_stats[5] if risk_stats[5] else 0.0,
            },
        }

    def query_production_touches(
        self,
        agent_id: Optional[str] = None,
        min_risk: Optional[float] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list:
        """
        Query production touches with optional filters.

        Args:
            agent_id: Filter by agent ID
            min_risk: Minimum overall risk score
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of results

        Returns:
            List of production touch audit entries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM audit_log WHERE is_production_touch = 1"
        params = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if min_risk is not None:
            query += " AND overall_risk >= ?"
            params.append(min_risk)

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return results

    def query_by_risk_category(
        self,
        risk_category: str,
        min_risk: float = 0.5,
        limit: int = 100,
    ) -> list:
        """
        Query actions by specific risk category.

        Args:
            risk_category: 'security', 'privacy', 'reliability', or 'compliance'
            min_risk: Minimum risk score for the category
            limit: Maximum number of results

        Returns:
            List of audit entries matching the risk criteria
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        risk_column_map = {
            "security": "security_risk",
            "privacy": "privacy_risk",
            "reliability": "reliability_risk",
            "compliance": "compliance_risk",
        }

        risk_column = risk_column_map.get(risk_category)
        if not risk_column:
            raise ValueError(
                f"Invalid risk category: {risk_category}. "
                f"Must be one of {list(risk_column_map.keys())}"
            )

        query = f"SELECT * FROM audit_log WHERE {risk_column} >= ? ORDER BY {risk_column} DESC LIMIT ?"
        cursor.execute(query, (min_risk, limit))
        results = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return results

    def get_risk_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive risk summary across all tracked actions.

        Returns:
            Dictionary with risk breakdown and highlights
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # High risk actions (overall_risk > 0.7)
        cursor.execute(
            """
            SELECT COUNT(*) FROM audit_log WHERE overall_risk > 0.7
        """
        )
        high_risk_count = cursor.fetchone()[0]

        # Production touches by environment
        cursor.execute(
            """
            SELECT environment, COUNT(*) as count 
            FROM audit_log 
            WHERE environment IS NOT NULL
            GROUP BY environment
        """
        )
        by_environment = {row[0]: row[1] for row in cursor.fetchall()}

        # Top risk factors
        cursor.execute(
            """
            SELECT risk_factors FROM audit_log 
            WHERE risk_factors IS NOT NULL 
            LIMIT 1000
        """
        )
        all_factors = []
        for row in cursor.fetchall():
            if row[0]:
                try:
                    factors = json.loads(row[0])
                    all_factors.extend(factors)
                except json.JSONDecodeError:
                    pass

        # Count risk factor occurrences
        factor_counts = Counter(all_factors)
        top_risk_factors = [
            {"factor": factor, "count": count}
            for factor, count in factor_counts.most_common(10)
        ]

        # Actions by risk category
        cursor.execute(
            """
            SELECT 
                COUNT(CASE WHEN security_risk > 0.5 THEN 1 END) as high_security,
                COUNT(CASE WHEN privacy_risk > 0.5 THEN 1 END) as high_privacy,
                COUNT(CASE WHEN reliability_risk > 0.5 THEN 1 END) as high_reliability,
                COUNT(CASE WHEN compliance_risk > 0.5 THEN 1 END) as high_compliance
            FROM audit_log
        """
        )
        category_counts = cursor.fetchone()

        conn.close()

        return {
            "high_risk_actions": high_risk_count,
            "by_environment": by_environment,
            "top_risk_factors": top_risk_factors,
            "high_risk_by_category": {
                "security": category_counts[0],
                "privacy": category_counts[1],
                "reliability": category_counts[2],
                "compliance": category_counts[3],
            },
        }

    def close(self):
        """Clean up resources"""
        pass  # SQLite connections are opened/closed per operation

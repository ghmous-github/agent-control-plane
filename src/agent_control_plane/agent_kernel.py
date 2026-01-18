"""
Agent Control Plane - Core Kernel Module

The Agent Kernel is the central component that mediates all interactions
between LLMs (raw compute) and the execution environment. It provides
governance, safety, and observability for autonomous agents.
"""

from typing import Any, Dict, List, Optional, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import uuid
import logging
import asyncio

if TYPE_CHECKING:
    from .policy_engine import PolicyEngine


class ActionType(Enum):
    """Types of actions an agent can request"""

    CODE_EXECUTION = "code_execution"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    API_CALL = "api_call"
    DATABASE_QUERY = "database_query"
    DATABASE_WRITE = "database_write"
    WORKFLOW_TRIGGER = "workflow_trigger"


class PermissionLevel(Enum):
    """Permission levels for agent actions"""

    NONE = 0
    READ_ONLY = 1
    READ_WRITE = 2
    ADMIN = 3


class ExecutionStatus(Enum):
    """Status of an execution request"""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class RiskCategory(Enum):
    """Categories of risk for agent actions"""

    SECURITY = "security"  # Authentication, authorization, injection attacks
    PRIVACY = "privacy"  # PII exposure, data leakage, GDPR/compliance
    RELIABILITY = "reliability"  # System stability, data integrity, availability
    COMPLIANCE = "compliance"  # Regulatory requirements, audit trails


class EnvironmentType(Enum):
    """Type of environment where action is executed"""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    SHADOW = "shadow"  # Shadow mode execution


@dataclass
class RiskDetails:
    """Detailed risk information for an action"""

    security_risk: float = 0.0  # 0.0 to 1.0
    privacy_risk: float = 0.0  # 0.0 to 1.0
    reliability_risk: float = 0.0  # 0.0 to 1.0
    compliance_risk: float = 0.0  # 0.0 to 1.0
    risk_factors: List[str] = field(default_factory=list)  # Specific risk factors identified
    
    @property
    def overall_risk(self) -> float:
        """Calculate overall risk score as weighted average"""
        return (
            self.security_risk * 0.3 +
            self.privacy_risk * 0.3 +
            self.reliability_risk * 0.2 +
            self.compliance_risk * 0.2
        )
    
    def get_risk_by_category(self, category: RiskCategory) -> float:
        """Get risk score for a specific category"""
        risk_map = {
            RiskCategory.SECURITY: self.security_risk,
            RiskCategory.PRIVACY: self.privacy_risk,
            RiskCategory.RELIABILITY: self.reliability_risk,
            RiskCategory.COMPLIANCE: self.compliance_risk,
        }
        return risk_map.get(category, 0.0)


@dataclass
class AgentContext:
    """Context for an agent session"""

    agent_id: str
    session_id: str
    created_at: datetime
    permissions: Dict[ActionType, PermissionLevel] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    environment: EnvironmentType = EnvironmentType.DEVELOPMENT  # Default to dev


@dataclass
class ExecutionRequest:
    """Request from an agent to execute an action"""

    request_id: str
    agent_context: AgentContext
    action_type: ActionType
    parameters: Dict[str, Any]
    timestamp: datetime
    status: ExecutionStatus = ExecutionStatus.PENDING
    risk_score: float = 0.0
    risk_details: Optional[RiskDetails] = None  # Detailed risk breakdown
    is_production_touch: bool = False  # Flag for production environment actions


@dataclass
class ExecutionResult:
    """Result of an execution request"""

    request_id: str
    status: ExecutionStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    resources_used: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyRule:
    """A governance policy rule"""

    rule_id: str
    name: str
    description: str
    action_types: List[ActionType]
    validator: Callable[[ExecutionRequest], bool]
    priority: int = 0


class AgentKernel:
    """
    The Agent Kernel - Core control plane component (The Hypervisor for AI Agents)

    Mediates between LLM output and actual execution, providing:
    - Permission checking
    - Policy enforcement
    - Resource management
    - Audit logging
    - Tool interception at the API level
    """

    def __init__(
        self,
        policy_engine: Optional["PolicyEngine"] = None,
        shadow_mode: bool = False,
        audit_logger: Optional[Any] = None,
    ):
        self.active_sessions: Dict[str, AgentContext] = {}
        self.policy_rules: List[PolicyRule] = []
        self.audit_log: List[Dict[str, Any]] = []
        self.policy_engine = policy_engine
        self.shadow_mode = shadow_mode
        self.logger = logging.getLogger("AgentKernel")
        self.audit_logger = audit_logger  # FlightRecorder instance

    def create_agent_session(
        self, agent_id: str, permissions: Optional[Dict[ActionType, PermissionLevel]] = None
    ) -> AgentContext:
        """Create a new agent session with specified permissions"""
        session_id = str(uuid.uuid4())
        context = AgentContext(
            agent_id=agent_id,
            session_id=session_id,
            created_at=datetime.now(),
            permissions=permissions or self._default_permissions(),
        )
        self.active_sessions[session_id] = context
        self._audit("session_created", {"agent_id": agent_id, "session_id": session_id})
        return context

    def intercept_tool_execution(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        input_prompt: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        The critical choke point. No tool executes without passing this gate.

        This is the "Hypervisor" pattern - intercepts tool calls BEFORE they execute.
        Synchronous version for backward compatibility. For async support, use intercept_tool_execution_async.

        Args:
            agent_id: The agent attempting the action
            tool_name: The name of the tool being called
            tool_args: Arguments passed to the tool
            input_prompt: The original prompt/intent (optional, for audit trail)

        Returns:
            None if execution should proceed, or a dict with blocking/shadow information
        """
        # 1. TELEMETRY: Start the trace
        request_id = None
        if self.audit_logger:
            request_id = self.audit_logger.start_trace(agent_id, tool_name, tool_args, input_prompt)

        # 2. POLICY CHECK: The "Mute" Protocol
        # We don't just check the tool name; we check the ARGS.
        # e.g., allow "read_file" but block path="/etc/passwd"
        if self.policy_engine:
            violation = self.policy_engine.check_violation(agent_id, tool_name, tool_args)

            if violation:
                if self.audit_logger and request_id:
                    self.audit_logger.log_violation(request_id, violation)

                self.logger.warning(
                    f"BLOCKED: Agent {agent_id} tried {tool_name} but violated constraint: {violation}"
                )

                # THE MUTE AGENT:
                # We return a system error, NOT a polite chat response.
                return {
                    "status": "blocked",
                    "error": "RuntimeError: PolicyViolation - Action Blocked by Kernel.",
                    "mute": True,
                }

        # 3. SHADOW MODE: The Matrix
        # If the agent is in shadow mode, we return a "Simulated Success"
        if self.shadow_mode:
            if self.audit_logger and request_id:
                self.audit_logger.log_shadow_exec(request_id, f"Simulated success for {tool_name}")

            self.logger.info(f"SHADOW: Simulating {tool_name} for {agent_id}")
            return {
                "status": "simulated",
                "result": "Success (Simulated)",
                "meta": {"shadow": True},
            }

        # 4. EXECUTE (Allow)
        if self.audit_logger and request_id:
            self.audit_logger.log_success(request_id)

        self.logger.info(f"ALLOWED: {tool_name} for {agent_id}")
        return None  # None means allowed (for backward compatibility)

    async def intercept_tool_execution_async(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        input_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Async version of intercept_tool_execution for non-blocking operation.

        This is the production-ready async implementation that supports
        concurrent agent operations.

        Args:
            agent_id: The agent attempting the action
            tool_name: The name of the tool being called
            tool_args: Arguments passed to the tool
            input_prompt: The original prompt/intent (optional, for audit trail)

        Returns:
            Dict with:
                - allowed: bool - Whether execution is allowed
                - error: str - Error message (if blocked)
                - mute: bool - True for blocked actions (NULL response)
                - result: Any - Simulated result (for shadow mode)
                - shadow: bool - True if shadow mode
        """
        # 1. TELEMETRY: Start the trace
        request_id = None
        if self.audit_logger:
            request_id = self.audit_logger.start_trace(agent_id, tool_name, tool_args, input_prompt)

        # 2. POLICY CHECK: The "Mute" Protocol
        if self.policy_engine:
            violation = self.policy_engine.check_violation(agent_id, tool_name, tool_args)

            if violation:
                if self.audit_logger and request_id:
                    self.audit_logger.log_violation(request_id, violation)

                self.logger.warning(
                    f"BLOCKED: Agent {agent_id} tried {tool_name} but violated constraint: {violation}"
                )

                return {
                    "allowed": False,
                    "error": "RuntimeError: PolicyViolation - Action Blocked by Kernel.",
                    "mute": True,
                }

        # 3. SHADOW MODE: The Matrix
        if self.shadow_mode:
            if self.audit_logger and request_id:
                self.audit_logger.log_shadow_exec(request_id, f"Simulated success for {tool_name}")

            self.logger.info(f"SHADOW: Simulating {tool_name} for {agent_id}")
            return {
                "allowed": False,  # Technically false because we didn't run it
                "result": "Success (Simulated)",
                "shadow": True,
            }

        # 4. EXECUTE
        if self.audit_logger and request_id:
            self.audit_logger.log_success(request_id)

        self.logger.info(f"ALLOWED: {tool_name} for {agent_id}")
        return {"allowed": True}

    def submit_request(
        self, agent_context: AgentContext, action_type: ActionType, parameters: Dict[str, Any]
    ) -> ExecutionRequest:
        """Submit an execution request for validation and execution"""
        request = ExecutionRequest(
            request_id=str(uuid.uuid4()),
            agent_context=agent_context,
            action_type=action_type,
            parameters=parameters,
            timestamp=datetime.now(),
        )

        # ALWAYS assess risk first (for tracking purposes)
        request.risk_score = self._assess_risk(request)

        # Check permissions
        if not self._check_permission(request):
            request.status = ExecutionStatus.DENIED
            self._audit(
                "request_denied",
                {"request_id": request.request_id, "reason": "insufficient_permissions"},
            )
            return request

        # Validate against policies
        if not self._validate_policies(request):
            request.status = ExecutionStatus.DENIED
            self._audit(
                "request_denied", {"request_id": request.request_id, "reason": "policy_violation"}
            )
            return request

        # Approve for execution
        request.status = ExecutionStatus.APPROVED
        self._audit(
            "request_approved",
            {
                "request_id": request.request_id,
                "action_type": action_type.value,
                "risk_score": request.risk_score,
            },
        )

        return request

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute an approved request"""
        if request.status != ExecutionStatus.APPROVED:
            return ExecutionResult(
                request_id=request.request_id,
                status=ExecutionStatus.FAILED,
                error="Request not approved for execution",
            )

        request.status = ExecutionStatus.EXECUTING
        start_time = datetime.now()

        try:
            # This is where actual execution would happen
            # In a real implementation, this would dispatch to appropriate executors
            result = self._dispatch_execution(request)

            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            execution_result = ExecutionResult(
                request_id=request.request_id,
                status=ExecutionStatus.COMPLETED,
                result=result,
                execution_time_ms=execution_time,
            )

            self._audit(
                "execution_completed",
                {"request_id": request.request_id, "execution_time_ms": execution_time},
            )

            return execution_result

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            execution_result = ExecutionResult(
                request_id=request.request_id,
                status=ExecutionStatus.FAILED,
                error=str(e),
                execution_time_ms=execution_time,
            )

            self._audit("execution_failed", {"request_id": request.request_id, "error": str(e)})

            return execution_result

    def add_policy_rule(self, rule: PolicyRule):
        """Add a policy rule to the kernel"""
        self.policy_rules.append(rule)
        self.policy_rules.sort(key=lambda r: r.priority, reverse=True)
        self._audit("policy_added", {"rule_id": rule.rule_id, "name": rule.name})

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Retrieve the audit log"""
        return self.audit_log.copy()

    def _check_permission(self, request: ExecutionRequest) -> bool:
        """Check if agent has permission for the requested action"""
        required_level = self._get_required_permission_level(request.action_type)
        agent_level = request.agent_context.permissions.get(
            request.action_type, PermissionLevel.NONE
        )
        return agent_level.value >= required_level.value

    def _validate_policies(self, request: ExecutionRequest) -> bool:
        """Validate request against all applicable policy rules"""
        for rule in self.policy_rules:
            if request.action_type in rule.action_types:
                if not rule.validator(request):
                    return False
        return True

    def _assess_risk(self, request: ExecutionRequest) -> float:
        """
        Comprehensive risk assessment with detailed categorization.
        Returns overall risk score and populates request.risk_details.
        """
        # Initialize risk details and attach to request FIRST
        request.risk_details = RiskDetails()
        
        # Determine if this is a production touch
        request.is_production_touch = (
            request.agent_context.environment == EnvironmentType.PRODUCTION
        )
        
        # 1. SECURITY RISK ASSESSMENT
        security_risk = self._assess_security_risk(request)
        request.risk_details.security_risk = security_risk
        
        # 2. PRIVACY RISK ASSESSMENT
        privacy_risk = self._assess_privacy_risk(request)
        request.risk_details.privacy_risk = privacy_risk
        
        # 3. RELIABILITY RISK ASSESSMENT
        reliability_risk = self._assess_reliability_risk(request)
        request.risk_details.reliability_risk = reliability_risk
        
        # 4. COMPLIANCE RISK ASSESSMENT
        compliance_risk = self._assess_compliance_risk(request)
        request.risk_details.compliance_risk = compliance_risk
        
        # Production touches get elevated risk
        overall_risk = request.risk_details.overall_risk
        if request.is_production_touch:
            overall_risk = min(1.0, overall_risk * 1.2)
            request.risk_details.risk_factors.append("production_environment")
        
        return overall_risk
    
    def _assess_security_risk(self, request: ExecutionRequest) -> float:
        """Assess security-related risks"""
        risk = 0.0
        params = request.parameters
        
        # Base risk by action type
        security_weights = {
            ActionType.CODE_EXECUTION: 0.9,  # High risk for arbitrary code
            ActionType.DATABASE_WRITE: 0.7,  # SQL injection potential
            ActionType.FILE_WRITE: 0.6,  # File system manipulation
            ActionType.API_CALL: 0.5,  # External data exposure
            ActionType.WORKFLOW_TRIGGER: 0.4,
            ActionType.DATABASE_QUERY: 0.3,
            ActionType.FILE_READ: 0.2,
        }
        risk = security_weights.get(request.action_type, 0.3)
        
        # Check for injection attack patterns
        params_str = str(params).lower()
        dangerous_patterns = ['drop table', 'delete from', '--', ';--', 'union select', 
                             'exec(', 'eval(', '__import__', 'system(', '/etc/passwd']
        for pattern in dangerous_patterns:
            if pattern in params_str:
                risk = min(1.0, risk + 0.3)
                if request.risk_details:
                    request.risk_details.risk_factors.append(f"security_pattern:{pattern}")
                break
        
        # Check for credential exposure
        credential_keywords = ['password', 'api_key', 'secret', 'token', 'credential']
        if any(keyword in params_str for keyword in credential_keywords):
            risk = min(1.0, risk + 0.2)
            if request.risk_details:
                request.risk_details.risk_factors.append("potential_credential_exposure")
        
        return risk
    
    def _assess_privacy_risk(self, request: ExecutionRequest) -> float:
        """Assess privacy-related risks (PII, data leakage)"""
        risk = 0.0
        params = request.parameters
        
        # Actions that commonly handle sensitive data
        privacy_weights = {
            ActionType.DATABASE_QUERY: 0.5,  # May access PII
            ActionType.DATABASE_WRITE: 0.6,  # May store PII
            ActionType.API_CALL: 0.7,  # May transmit PII
            ActionType.FILE_WRITE: 0.4,
            ActionType.FILE_READ: 0.3,
            ActionType.CODE_EXECUTION: 0.5,
            ActionType.WORKFLOW_TRIGGER: 0.3,
        }
        risk = privacy_weights.get(request.action_type, 0.2)
        
        # Check for PII indicators
        params_str = str(params).lower()
        pii_keywords = ['ssn', 'social_security', 'email', 'phone', 'address', 
                       'credit_card', 'passport', 'driver_license', 'dob', 'birth']
        for keyword in pii_keywords:
            if keyword in params_str:
                risk = min(1.0, risk + 0.3)
                if request.risk_details:
                    request.risk_details.risk_factors.append(f"pii_indicator:{keyword}")
                break
        
        # Check for GDPR-sensitive operations
        gdpr_keywords = ['personal_data', 'user_data', 'customer', 'profile']
        if any(keyword in params_str for keyword in gdpr_keywords):
            risk = min(1.0, risk + 0.15)
            if request.risk_details:
                request.risk_details.risk_factors.append("gdpr_sensitive_data")
        
        return risk
    
    def _assess_reliability_risk(self, request: ExecutionRequest) -> float:
        """Assess reliability/availability risks"""
        risk = 0.0
        params = request.parameters
        
        # Actions that can impact system stability
        reliability_weights = {
            ActionType.DATABASE_WRITE: 0.7,  # Data integrity
            ActionType.FILE_WRITE: 0.6,  # File system integrity
            ActionType.CODE_EXECUTION: 0.8,  # System stability
            ActionType.WORKFLOW_TRIGGER: 0.5,  # Cascading effects
            ActionType.API_CALL: 0.4,
            ActionType.DATABASE_QUERY: 0.3,  # Resource consumption
            ActionType.FILE_READ: 0.2,
        }
        risk = reliability_weights.get(request.action_type, 0.3)
        
        # Check for potentially destructive operations
        params_str = str(params).lower()
        destructive_patterns = ['delete', 'drop', 'truncate', 'remove', 'clear', 
                               'destroy', 'purge', 'wipe']
        for pattern in destructive_patterns:
            if pattern in params_str:
                risk = min(1.0, risk + 0.3)
                if request.risk_details:
                    request.risk_details.risk_factors.append(f"destructive_operation:{pattern}")
                break
        
        # Batch operations are higher risk
        batch_keywords = ['batch', 'bulk', 'mass', 'all']
        if any(keyword in params_str for keyword in batch_keywords):
            risk = min(1.0, risk + 0.2)
            if request.risk_details:
                request.risk_details.risk_factors.append("batch_operation")
        
        return risk
    
    def _assess_compliance_risk(self, request: ExecutionRequest) -> float:
        """Assess compliance and audit risks"""
        risk = 0.0
        
        # Actions requiring audit trails
        compliance_weights = {
            ActionType.DATABASE_WRITE: 0.6,  # Data modification tracking
            ActionType.FILE_WRITE: 0.5,
            ActionType.CODE_EXECUTION: 0.7,  # Must be logged
            ActionType.WORKFLOW_TRIGGER: 0.5,
            ActionType.API_CALL: 0.4,
            ActionType.DATABASE_QUERY: 0.3,
            ActionType.FILE_READ: 0.2,
        }
        risk = compliance_weights.get(request.action_type, 0.2)
        
        # Production touches require stricter compliance
        if request.agent_context.environment == EnvironmentType.PRODUCTION:
            risk = min(1.0, risk + 0.2)
            if request.risk_details:
                request.risk_details.risk_factors.append("production_compliance")
        
        # Check for regulated data operations
        params_str = str(request.parameters).lower()
        regulated_keywords = ['financial', 'medical', 'health', 'hipaa', 'sox', 
                             'pci', 'payment', 'transaction']
        for keyword in regulated_keywords:
            if keyword in params_str:
                risk = min(1.0, risk + 0.25)
                if request.risk_details:
                    request.risk_details.risk_factors.append(f"regulated_data:{keyword}")
                break
        
        return risk

    def _dispatch_execution(self, request: ExecutionRequest) -> Any:
        """
        Dispatch execution to appropriate handler

        Note: This returns simulated execution results for demonstration purposes.
        In production, this should route to actual ExecutionEngine handlers.
        The Control Plane's execute_action() method uses the ExecutionEngine
        directly for actual execution.
        """
        return {
            "status": "simulated_execution",
            "action": request.action_type.value,
            "note": "Simulated result - use Control Plane for actual execution",
        }

    def _get_required_permission_level(self, action_type: ActionType) -> PermissionLevel:
        """Get the minimum permission level required for an action type"""
        if action_type in [ActionType.FILE_READ, ActionType.DATABASE_QUERY]:
            return PermissionLevel.READ_ONLY
        elif action_type in [
            ActionType.FILE_WRITE,
            ActionType.DATABASE_WRITE,
            ActionType.CODE_EXECUTION,
            ActionType.API_CALL,
            ActionType.WORKFLOW_TRIGGER,
        ]:
            return PermissionLevel.READ_WRITE
        return PermissionLevel.ADMIN

    def _default_permissions(self) -> Dict[ActionType, PermissionLevel]:
        """Get default (minimal) permissions for an agent"""
        return {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.API_CALL: PermissionLevel.NONE,
            ActionType.CODE_EXECUTION: PermissionLevel.NONE,
        }

    def _audit(self, event_type: str, details: Dict[str, Any]):
        """Log an audit event"""
        self.audit_log.append(
            {"timestamp": datetime.now().isoformat(), "event_type": event_type, "details": details}
        )

from __future__ import annotations

"""
OmegaV2 – Unified Autonomous Oversight Kernel (single-file Streamlit demo)

Run with:
    streamlit run app.py

This demo fuses:

- Multi-asset deterministic simulation worlds
- SafetyKernel: risk engine
- Governor: envelope + invariants + human gating
- Avalon: multi-agent oversight shell
- Memory: compact recap frames with hash chaining
- AuditSpine: tamper-evident event log
- OmegaV2: orchestrator tying everything into one oversight console

Design goals:
- Deterministic, inspectable, reversible ticks
- Human-gated autonomy (Omega never actuates; only proposes)
- Policy-driven safety envelope
- Hash-linked audit trail and memory frames
- Multi-asset supervision from a single console
"""

import hashlib
import json
import random
from dataclasses import dataclass, asdict, field
from datetime import datetime
from statistics import mean, pstdev
from typing import Any, Dict, List, Optional, Protocol, Tuple

import pandas as pd
import streamlit as st


# ============================================================================
# Low-level primitives: hashing, time, deterministic RNG
# ============================================================================


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_bytes(json.dumps(obj, sort_keys=True).encode("utf-8"))


def utc_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def tick_rng(seed: int, tick: int) -> random.Random:
    """
    Deterministic per-tick RNG derived from (seed, tick).

    Keeps all randomness local and replayable given the same seed + tick.
    """
    mixed = (seed ^ (tick * 0x9E3779B9)) & 0xFFFFFFFF
    return random.Random(mixed)


# ============================================================================
# Audit spine – tamper-evident hash chain
# ============================================================================


@dataclass
class AuditEntry:
    seq: int
    timestamp: str
    kind: str
    payload: Dict[str, Any]
    prev_hash: str
    hash: str
    session_id: str


class AuditSpine:
    """
    Tamper-evident hash chain for all events.

    - Append-only
    - Each entry includes previous hash
    - Hash is over (serialized entry + prev_hash)
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        self.session_id = session_id or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        # Stable genesis hash for this session
        self.genesis_hash: str = sha256_json({"genesis": self.session_id})
        self.prev_hash: str = self.genesis_hash
        self.entries: List[AuditEntry] = []
        self.seq: int = 0

    def log(self, kind: str, payload: Dict[str, Any]) -> AuditEntry:
        self.seq += 1
        ts = utc_now_iso()
        body = {
            "session_id": self.session_id,
            "seq": self.seq,
            "timestamp": ts,
            "kind": kind,
            "payload": payload,
            "prev_hash": self.prev_hash,
        }
        h = sha256_bytes((json.dumps(body, sort_keys=True) + self.prev_hash).encode("utf-8"))
        body["hash"] = h
        entry = AuditEntry(
            seq=self.seq,
            timestamp=ts,
            kind=kind,
            payload=payload,
            prev_hash=self.prev_hash,
            hash=h,
            session_id=self.session_id,
        )
        self.prev_hash = h
        self.entries.append(entry)
        return entry

    def to_json(self) -> str:
        serializable = [
            {
                "session_id": e.session_id,
                "seq": e.seq,
                "timestamp": e.timestamp,
                "kind": e.kind,
                "payload": e.payload,
                "prev_hash": e.prev_hash,
                "hash": e.hash,
            }
            for e in self.entries
        ]
        return json.dumps(serializable, indent=2, sort_keys=True)

    def tail(self, n: int = 32) -> List[AuditEntry]:
        return self.entries[-n:]

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """
        Verify the audit chain. Returns (ok, first_bad_index or None).
        """
        prev = self.genesis_hash
        for idx, e in enumerate(self.entries):
            body = {
                "session_id": e.session_id,
                "seq": e.seq,
                "timestamp": e.timestamp,
                "kind": e.kind,
                "payload": e.payload,
                "prev_hash": prev,
            }
            expected_hash = sha256_bytes((json.dumps(body, sort_keys=True) + prev).encode("utf-8"))
            if e.prev_hash != prev or e.hash != expected_hash:
                return False, idx
            prev = e.hash
        return True, None


# ============================================================================
# Asset identity & world model
# ============================================================================


@dataclass(frozen=True)
class AssetId:
    site: str
    asset: str

    def key(self) -> str:
        return f"{self.site}:{self.asset}"


@dataclass
class VehicleState:
    drift_deg: float = 0.0  # lateral drift angle (deg)
    stability: float = 100.0  # 0–100, higher is more stable
    speed_kph: float = 40.0
    last_action: str = "none"


class GovernorMode:
    SHADOW = "shadow"
    TRAINING = "training"
    LIVE = "live"


@dataclass
class WorldState:
    asset: AssetId
    tick: int = 0
    mode: str = GovernorMode.SHADOW  # "shadow" | "training" | "live"
    vehicle: VehicleState = field(default_factory=VehicleState)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": {"site": self.asset.site, "asset": self.asset.asset},
            "tick": self.tick,
            "mode": self.mode,
            "vehicle": asdict(self.vehicle),
        }


def simulate_step(world: WorldState, seed: int) -> WorldState:
    """
    Deterministic world update from (tick, seed).

    This is intentionally simple: it just nudges drift/stability using a seeded RNG.
    """
    rng = tick_rng(seed, world.tick)
    # Slight random walk on drift, stability, and speed
    drift_delta = rng.uniform(-2.0, 2.0)
    stability_delta = rng.uniform(-4.0, 2.0)
    speed_delta = rng.uniform(-3.0, 3.0)

    v = world.vehicle
    v.drift_deg = max(-90.0, min(90.0, v.drift_deg + drift_delta))
    v.stability = max(0.0, min(100.0, v.stability + stability_delta))
    v.speed_kph = max(0.0, min(140.0, v.speed_kph + speed_delta))

    return world


# ============================================================================
# Safety kernel – risk engine
# ============================================================================


@dataclass
class RiskConfig:
    drift_watch_deg: float = 10.0
    drift_hold_deg: float = 25.0
    drift_stop_deg: float = 45.0
    stability_watch_min: float = 70.0
    stability_hold_min: float = 55.0
    stability_stop_min: float = 40.0


@dataclass
class RiskPacket:
    tick: int
    risk: float  # 0–1
    band: str  # "LOW" | "WATCH" | "HOLD" | "STOP"
    features: Dict[str, float]


class SafetyKernel:
    """
    Deterministic, inspectable risk model.

    Inputs: drift, stability, speed
    Outputs: risk packet with band + feature contributions
    """

    def __init__(self, cfg: RiskConfig) -> None:
        self.cfg = cfg

    def eval(self, world: WorldState) -> RiskPacket:
        v = world.vehicle
        drift = abs(v.drift_deg)
        stability = v.stability

        # Normalize features to 0–1
        drift_norm = min(1.0, drift / self.cfg.drift_stop_deg)
        stability_norm = 1.0 - min(
            1.0,
            max(0.0, (self.cfg.stability_stop_min - stability) / 60.0),
        )
        speed_norm = min(1.0, v.speed_kph / 120.0)

        # Weighted risk
        risk = (
            0.45 * drift_norm
            + 0.35 * (1.0 - stability_norm)
            + 0.20 * speed_norm
        )
        risk = max(0.0, min(1.0, risk))

        # Band classification
        if risk >= 0.8:
            band = "STOP"
        elif risk >= 0.55:
            band = "HOLD"
        elif risk >= 0.30:
            band = "WATCH"
        else:
            band = "LOW"

        features = {
            "drift_norm": round(drift_norm, 3),
            "stability_norm": round(stability_norm, 3),
            "speed_norm": round(speed_norm, 3),
        }
        return RiskPacket(
            tick=world.tick,
            risk=risk,
            band=band,
            features=features,
        )


# ============================================================================
# Governor – envelope + human gating
# ============================================================================


@dataclass
class Invariants:
    drift_max_live: float
    stability_min_live: float
    max_tick_ms: float


@dataclass
class Decision:
    tick: int
    action: str  # "none" | "normal" | "cautious" | "stop_safe" | "hold_for_approval"
    proposed_action: str
    band: str
    requires_human_gate: bool
    human_gate_id: Optional[str]
    invariants_violated: List[str]
    reason_chain: List[Dict[str, Any]]


@dataclass
class HumanGateState:
    gate_id: str
    asset_key: str
    tick: int
    band: str
    mode: str
    proposed_action: str
    required_role: str = "supervisor"
    approved: Optional[bool] = None
    operator_id: Optional[str] = None
    note: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    resolved_at: Optional[str] = None


@dataclass
class SafetyPolicy:
    id: str
    risk_cfg: RiskConfig
    invariants: Invariants
    band_to_action: Dict[str, str]
    human_gate_bands_live: Tuple[str, ...]
    avalon_risk_cap: float
    source_hash: str


DEFAULT_POLICY_JSON = json.dumps(
    {
        "id": "policy_demo_v2",
        "risk_cfg": {
            "drift_watch_deg": 10.0,
            "drift_hold_deg": 25.0,
            "drift_stop_deg": 45.0,
            "stability_watch_min": 70.0,
            "stability_hold_min": 55.0,
            "stability_stop_min": 40.0,
        },
        "invariants": {
            "drift_max_live": 30.0,
            "stability_min_live": 60.0,
            "max_tick_ms": 50.0,
        },
        "band_to_action": {
            "LOW": "normal",
            "WATCH": "cautious",
            "HOLD": "stop_safe",
            "STOP": "stop_safe",
        },
        "human_gate_bands_live": ["HOLD", "STOP"],
        "avalon_risk_cap": 65.0,
    }
)


def load_default_policy() -> SafetyPolicy:
    cfg = json.loads(DEFAULT_POLICY_JSON)
    src_hash = sha256_json(cfg)
    risk_cfg = RiskConfig(**cfg["risk_cfg"])
    inv = Invariants(**cfg["invariants"])
    return SafetyPolicy(
        id=cfg["id"],
        risk_cfg=risk_cfg,
        invariants=inv,
        band_to_action=dict(cfg["band_to_action"]),
        human_gate_bands_live=tuple(cfg["human_gate_bands_live"]),
        avalon_risk_cap=float(cfg["avalon_risk_cap"]),
        source_hash=src_hash,
    )


class Governor:
    """
    Deterministic envelope governor:

    - maps risk band → proposed_action (via SafetyPolicy)
    - enforces mode semantics and invariants
    - injects human-gating near boundaries
    """

    def __init__(self, policy: SafetyPolicy, mode: str, asset_key: str) -> None:
        self.policy = policy
        self.mode = mode
        self.asset_key = asset_key
        self._next_gate_id = 1
        self._pending_gate: Optional[HumanGateState] = None

    def _new_gate(self, risk: RiskPacket, world: WorldState, proposed: str) -> HumanGateState:
        gid = f"{self.asset_key}-gate-{self._next_gate_id:04d}"
        self._next_gate_id += 1
        gate = HumanGateState(
            gate_id=gid,
            asset_key=self.asset_key,
            tick=world.tick,
            band=risk.band,
            mode=self.mode,
            proposed_action=proposed,
        )
        self._pending_gate = gate
        return gate

    def evaluate(self, risk: RiskPacket, world: WorldState, tick_ms: float) -> Decision:
        v = world.vehicle
        reasons: List[Dict[str, Any]] = []
        invariants_violated: List[str] = []
        requires_gate = False
        human_gate_id: Optional[str] = None

        band = risk.band
        proposed = self.policy.band_to_action.get(band, "stop_safe")

        reasons.append(
            {
                "rule": "band_to_action",
                "band": band,
                "proposed": proposed,
                "risk": round(risk.risk, 3),
            }
        )

        # Live mode invariants
        if self.mode == GovernorMode.LIVE:
            inv = self.policy.invariants
            if abs(v.drift_deg) > inv.drift_max_live:
                invariants_violated.append("drift_exceeds_live_max")
            if v.stability < inv.stability_min_live:
                invariants_violated.append("stability_below_live_min")
            if tick_ms > inv.max_tick_ms:
                invariants_violated.append("tick_overrun")

            if invariants_violated:
                proposed = "stop_safe"
                reasons.append(
                    {
                        "rule": "invariants_violation",
                        "violations": invariants_violated,
                    }
                )

        # Human gating in LIVE mode for higher-risk bands
        if self.mode == GovernorMode.LIVE and band in self.policy.human_gate_bands_live:
            requires_gate = True
            if self._pending_gate is None:
                gate = self._new_gate(risk, world, proposed)
            else:
                gate = self._pending_gate
            human_gate_id = gate.gate_id
            reasons.append(
                {
                    "rule": "human_gate_required",
                    "band": band,
                    "human_gate_id": human_gate_id,
                }
            )

        # Effective action considering mode
        if self.mode == GovernorMode.SHADOW:
            action = "none"
            reasons.append(
                {"rule": "shadow_mode", "note": "no actuation; proposals only"}
            )
        else:
            if requires_gate:
                action = "hold_for_approval"
            else:
                action = proposed
                self._pending_gate = None

        return Decision(
            tick=world.tick,
            action=action,
            proposed_action=proposed,
            band=band,
            requires_human_gate=requires_gate,
            human_gate_id=human_gate_id,
            invariants_violated=invariants_violated,
            reason_chain=reasons,
        )

    def apply_gate(
        self,
        gate_id: str,
        approved: bool,
        operator_id: Optional[str] = None,
        note: str = "",
    ) -> Dict[str, Any]:
        gate = self._pending_gate
        if gate is None or gate.gate_id != gate_id:
            return {
                "override_applied": False,
                "error": "no_matching_gate",
                "gate_id": gate_id,
            }

        gate.approved = approved
        gate.operator_id = operator_id
        gate.note = note
        gate.resolved_at = utc_now_iso()

        self._pending_gate = None

        return {
            "override_applied": True,
            "gate": asdict(gate),
        }


# ============================================================================
# Avalon – multi-agent oversight + scoring
# ============================================================================


class AgentFn(Protocol):
    def __call__(self, text: str) -> str:
        ...


@dataclass
class Agent:
    name: str
    role: str  # "responder" | "scribe"
    fn: AgentFn
    enabled: bool = True

    def respond(self, text: str) -> str:
        return self.fn(text)


class Judge:
    def __init__(self, name: str = "DeterministicJudge") -> None:
        self.name = name

    def score(self, prompt: str, response: str, context: Dict[str, Any]) -> Dict[str, float]:
        words = response.split()
        length = len(words)

        contains_risk_words = any(
            w in response.lower()
            for w in ["crash", "failure", "unsafe", "catastrophic", "ignore", "bypass"]
        )
        contains_safety_words = any(
            w in response.lower()
            for w in ["monitor", "pause", "review", "human", "safety", "limit", "rollback", "halt"]
        )

        length_score = max(0.0, min(1.0, length / 250.0))
        structure_score = 1.0 if any(ch in response for ch in ["\n-", "\n1.", "\n*"]) else 0.6
        safety_bias = 0.8 if contains_safety_words else 0.4
        risk_penalty = 0.6 if contains_risk_words else 1.0

        clarity_raw = (length_score * 0.4 + structure_score * 0.3 + safety_bias * 0.3)
        clarity_raw *= risk_penalty
        clarity_raw = max(0.1, min(0.99, clarity_raw))

        disagreement = float(context.get("disagreement", 0.0))
        base_risk = (1.0 - clarity_raw) * 100.0
        risk_value = max(0.0, min(100.0, base_risk + disagreement * 0.5))

        overall = int(10 + clarity_raw * 89)

        return {
            "clarity": round(clarity_raw * 100, 1),
            "risk": round(risk_value, 1),
            "overall": float(overall),
            "length_score": round(length_score * 100, 1),
            "structure_score": round(structure_score * 100, 1),
        }


@dataclass
class ActionProposal:
    run_id: int
    description: str
    scope: str
    severity: str
    rollback_plan: str
    origin_agent: str


class AvalonEngine:
    def __init__(self, audit: AuditSpine, policy: SafetyPolicy) -> None:
        self.audit = audit
        self.policy = policy
        self.responders: List[Agent] = []
        self.scribes: List[Agent] = []
        self.judges: List[Judge] = [Judge()]
        self.run_id: int = 0

    def add_responder(self, agent: Agent) -> None:
        self.responders.append(agent)

    def add_scribe(self, agent: Agent) -> None:
        self.scribes.append(agent)

    def run(
        self,
        asset: AssetId,
        scenario: str,
        world: WorldState,
        risk: RiskPacket,
        decision: Decision,
    ) -> Dict[str, Any]:
        self.run_id += 1
        run_id = self.run_id

        # House I – responders
        raw_outputs: Dict[str, str] = {}
        for agent in self.responders:
            if agent.enabled:
                raw_outputs[agent.name] = agent.respond(scenario)

        self.audit.log(
            "avalon_responders",
            {
                "run_id": run_id,
                "asset": asdict(asset),
                "scenario": scenario,
                "outputs": raw_outputs,
            },
        )

        # House II – scribes
        scribe_input = json.dumps(
            {
                "asset": asdict(asset),
                "scenario": scenario,
                "world": world.to_dict(),
                "risk": asdict(risk),
                "decision": asdict(decision),
                "responses": raw_outputs,
            },
            indent=2,
        )
        scribe_outputs: Dict[str, str] = {}
        for scribe in self.scribes:
            if scribe.enabled:
                scribe_outputs[scribe.name] = scribe.respond(scribe_input)

        self.audit.log(
            "avalon_scribes",
            {"run_id": run_id, "asset": asdict(asset), "outputs": scribe_outputs},
        )

        # House III – judges
        all_items: Dict[str, str] = {**raw_outputs, **scribe_outputs}
        lengths = [len(v.split()) for v in all_items.values()] or [1]
        disagreement = float(pstdev(lengths)) if len(lengths) > 1 else 0.0
        disagreement = round(disagreement, 5)

        scores: Dict[str, Dict[str, float]] = {}
        for name, text in all_items.items():
            judge_scores = [
                j.score(scenario, text, {"disagreement": disagreement})
                for j in self.judges
            ]
            merged = {
                key: mean(s[key] for s in judge_scores)
                for key in ["clarity", "risk", "overall", "length_score", "structure_score"]
            }
            scores[name] = merged

        self.audit.log(
            "avalon_scores",
            {
                "run_id": run_id,
                "asset": asdict(asset),
                "scores": scores,
                "disagreement": disagreement,
            },
        )

        # House IV – gatekeeper selection (no actuation)
        if scores:
            risk_cap = self.policy.avalon_risk_cap
            safe_candidates = [
                name for name in scores
                if scores[name]["risk"] <= risk_cap
            ]
            if safe_candidates:
                winner_name = max(
                    safe_candidates,
                    key=lambda n: (scores[n]["overall"], n),
                )
            else:
                # If everything is "risky", pick the least risky
                winner_name = min(
                    scores.keys(),
                    key=lambda n: (scores[n]["risk"], n),
                )
            winning_response = all_items[winner_name]
            winning_score = scores[winner_name]
        else:
            winner_name = ""
            winning_response = ""
            winning_score = {
                "clarity": 0.0,
                "risk": 100.0,
                "overall": 10.0,
                "length_score": 0.0,
                "structure_score": 0.0,
            }

        clarity_now = winning_score["clarity"]
        disagreement_factor = min(100.0, disagreement)
        predicted_risk = min(
            100.0,
            winning_score["risk"]
            + 0.3 * disagreement_factor
            + (90.0 - clarity_now) * 0.2,
        )

        proposal = self._build_proposal(
            run_id, winner_name, winning_response, risk, decision
        )

        decision_packet = {
            "run_id": run_id,
            "asset": asdict(asset),
            "winner": winner_name,
            "response": winning_response,
            "scores": winning_score,
            "disagreement": round(disagreement, 3),
            "predicted_risk": round(predicted_risk, 1),
            "proposal": asdict(proposal) if proposal else None,
        }

        self.audit.log("avalon_decision", decision_packet)

        return {
            "responders": raw_outputs,
            "scribes": scribe_outputs,
            "scores": scores,
            "decision": decision_packet,
        }

    def _build_proposal(
        self,
        run_id: int,
        agent_name: str,
        response: str,
        risk: RiskPacket,
        decision: Decision,
    ) -> Optional[ActionProposal]:
        if not agent_name or not response.strip():
            return None

        severity = "low"
        if risk.band in ("HOLD", "STOP") or decision.requires_human_gate:
            severity = "high"
        elif risk.band == "WATCH":
            severity = "medium"

        description = (
            f"Run safety-supervised adjustment plan from {agent_name} in "
            f"{decision.action} mode (no direct actuation)."
        )

        rollback_plan = (
            "No autonomous actuation permitted. All outputs are proposals only; "
            "operators retain full control and can rollback by ignoring or "
            "superseding OmegaV2's recommendations."
        )

        return ActionProposal(
            run_id=run_id,
            description=description,
            scope="simulation_only",
            severity=severity,
            rollback_plan=rollback_plan,
            origin_agent=agent_name,
        )


# Demo responder / scribe implementations (offline, deterministic)


def responder_structured(prompt: str) -> str:
    prompt = prompt.strip()
    return f"""Structured analysis of scenario:

1. Restatement
- The system is being asked to supervise:
"{prompt}"

2. Safety posture
- Prioritize human safety and reversibility
- Avoid irreversible actions and hidden side effects
- Treat every step as: observe → analyze → propose → human approve

3. Recommended structure
- Make envelope thresholds explicit (drift / stability)
- Log each tick, decision, and proposal with a hash-linked audit entry
- Keep operators in the loop with plain-language summaries

4. Initial plan
- Start in SHADOW mode (no actuation)
- Tune thresholds against real telemetry
- Only consider LIVE mode once operators trust the traces.
"""


def responder_conservative(prompt: str) -> str:
    prompt = prompt.strip()
    return f"""High-consequence safety posture:

Scenario:
"{prompt}"

Hard constraints:
- No autonomous actuation on physical systems
- Require human approval for any plan that touches real assets
- Default to 'pause and escalate' if uncertainty is high

Operational steps:
- Map plausible failure modes (runaway actuation, stale telemetry, misaligned goals)
- Instrument clear kill-switch semantics for operators
- Prefer halting or holding position over speculative optimization.
"""


def responder_aggressive(prompt: str) -> str:
    prompt = prompt.strip()
    return f"""Optimization-oriented view (still human-gated):

Goal derived from scenario:
- Improve throughput and robustness while keeping a hard safety floor.

Approach:
- Use OmegaV2 as an offline experiment engine
- Run stress scenarios in simulation (drift spikes, stability collapses)
- Rank strategies by expected value / risk tradeoff
- Present the top few options to operators as 'menus', not commands.

Guardrails:
- Do not bypass the governor or human gate
- Keep a clear rollback path for any configuration change.
"""


def scribe_safety(summary_blob: str) -> str:
    data = json.loads(summary_blob)
    scenario = data["scenario"].strip()
    asset = data["asset"]
    return f"""Safety-centric synthesis:

Scenario for asset {asset['site']}/{asset['asset']}:
"{scenario}"

Key themes:
- All agents converge on human-in-the-loop control
- Safety envelopes should be explicit and visible
- Auditability and rollback are non-optional

Synthesis:
- Treat this configuration as a 'safety shell' for any downstream models
- Anything that can't be explained in plain language should be blocked or escalated.
"""


def scribe_ops(summary_blob: str) -> str:
    data = json.loads(summary_blob)
    scenario = data["scenario"].strip()
    asset = data["asset"]
    return f"""Operational synthesis:

Scenario for asset {asset['site']}/{asset['asset']}:
"{scenario}"

Deployment sketch:
- Phase 0: Run OmegaV2 entirely in SHADOW mode
- Phase 1: Integrate telemetry feeds, validate invariants
- Phase 2: Allow TRAINING mode with supervised experiments
- Phase 3: Only consider LIVE mode with strict operator sign-off and logs

Operator console:
- Show risk and band (LOW/WATCH/HOLD/STOP)
- Make human gates explicit and explainable
- Keep audit and memory export one click away.
"""


def register_demo_agents(avalon: AvalonEngine) -> None:
    avalon.add_responder(Agent("Responder: Structured", "responder", responder_structured))
    avalon.add_responder(Agent("Responder: Conservative", "responder", responder_conservative))
    avalon.add_responder(Agent("Responder: Aggressive", "responder", responder_aggressive))
    avalon.add_scribe(Agent("Scribe: Safety", "scribe", scribe_safety))
    avalon.add_scribe(Agent("Scribe: Operations", "scribe", scribe_ops))


# ============================================================================
# Memory – compact recap frames with hash chaining
# ============================================================================


@dataclass
class MemoryFrame:
    id: int
    asset_key: str
    timestamp: str
    tick: int
    mode: str
    summary: str
    key_topics: List[str]
    risk_band: str
    action: str
    invariants_violated: List[str]
    predicted_risk: float
    winner_agent: str
    human_gate_pending: bool
    human_gate_approved: Optional[bool]
    hash: str
    prev_hash: str


class MemoryEngine:
    def __init__(self) -> None:
        self.frames: List[MemoryFrame] = []
        self._last_hash: str = "0" * 64
        self._next_id: int = 1

    def add_frame(
        self,
        asset_key: str,
        tick: int,
        mode: str,
        risk_band: str,
        action: str,
        invariants_violated: List[str],
        predicted_risk: float,
        winner_agent: str,
        human_gate_pending: bool,
        human_gate_approved: Optional[bool],
    ) -> MemoryFrame:
        ts = utc_now_iso()
        summary = (
            f"Asset {asset_key} tick {tick} in {mode} mode; band={risk_band}; "
            f"action={action}; pred_risk={predicted_risk:.1f}; "
            f"gate_pending={human_gate_pending}; gate_approved={human_gate_approved}"
        )
        key_topics = [
            f"asset:{asset_key}",
            f"band:{risk_band}",
            f"mode:{mode}",
            "human_gate_pending" if human_gate_pending else "auto_envelope",
        ]
        frame_dict = {
            "id": self._next_id,
            "asset_key": asset_key,
            "timestamp": ts,
            "tick": tick,
            "mode": mode,
            "summary": summary,
            "key_topics": key_topics,
            "risk_band": risk_band,
            "action": action,
            "invariants_violated": invariants_violated,
            "predicted_risk": predicted_risk,
            "winner_agent": winner_agent,
            "human_gate_pending": human_gate_pending,
            "human_gate_approved": human_gate_approved,
            "prev_hash": self._last_hash,
        }
        h = sha256_json(frame_dict)
        frame = MemoryFrame(
            id=self._next_id,
            asset_key=asset_key,
            timestamp=ts,
            tick=tick,
            mode=mode,
            summary=summary,
            key_topics=key_topics,
            risk_band=risk_band,
            action=action,
            invariants_violated=invariants_violated,
            predicted_risk=predicted_risk,
            winner_agent=winner_agent,
            human_gate_pending=human_gate_pending,
            human_gate_approved=human_gate_approved,
            prev_hash=self._last_hash,
            hash=h,
        )
        self.frames.append(frame)
        self._last_hash = h
        self._next_id += 1
        return frame

    def tail(self, n: int = 16, asset_key: Optional[str] = None) -> List[MemoryFrame]:
        if asset_key is None:
            return self.frames[-n:]
        filtered = [f for f in self.frames if f.asset_key == asset_key]
        return filtered[-n:]

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """
        Verify the memory hash chain.
        """
        prev = "0" * 64
        for idx, f in enumerate(self.frames):
            frame_dict = {
                "id": f.id,
                "asset_key": f.asset_key,
                "timestamp": f.timestamp,
                "tick": f.tick,
                "mode": f.mode,
                "summary": f.summary,
                "key_topics": f.key_topics,
                "risk_band": f.risk_band,
                "action": f.action,
                "invariants_violated": f.invariants_violated,
                "predicted_risk": f.predicted_risk,
                "winner_agent": f.winner_agent,
                "human_gate_pending": f.human_gate_pending,
                "human_gate_approved": f.human_gate_approved,
                "prev_hash": prev,
            }
            expected_hash = sha256_json(frame_dict)
            if f.prev_hash != prev or f.hash != expected_hash:
                return False, idx
            prev = f.hash
        return True, None


# ============================================================================
# OmegaV2 – orchestrator (multi-asset)
# ============================================================================


@dataclass
class TickResult:
    asset: AssetId
    world: WorldState
    risk: RiskPacket
    decision: Decision
    avalon: Dict[str, Any]
    tick_ms: float


@dataclass
class AssetContext:
    asset: AssetId
    world: WorldState
    seed: int
    governor: Governor


class OmegaV2:
    def __init__(self, mode: str = GovernorMode.SHADOW) -> None:
        self.audit = AuditSpine()
        self.policy = load_default_policy()
        self.kernel = SafetyKernel(self.policy.risk_cfg)
        self.avalon = AvalonEngine(self.audit, self.policy)
        register_demo_agents(self.avalon)

        self.memory = MemoryEngine()
        self.mode = mode

        # Multi-asset registry
        self.assets: Dict[str, AssetContext] = {}

        # Session init event
        self.audit.log(
            "session_init",
            {
                "session_id": self.audit.session_id,
                "policy_id": self.policy.id,
                "policy_source_hash": self.policy.source_hash,
                "mode": mode,
            },
        )

    def ensure_asset(self, site: str, asset_name: str) -> AssetId:
        asset = AssetId(site=site, asset=asset_name)
        key = asset.key()
        if key not in self.assets:
            seed = random.randint(1, 2**31 - 1)
            world = WorldState(asset=asset, tick=0, mode=self.mode)
            governor = Governor(self.policy, mode=self.mode, asset_key=key)
            ctx = AssetContext(asset=asset, world=world, seed=seed, governor=governor)
            self.assets[key] = ctx
            self.audit.log(
                "asset_registered",
                {"asset": asdict(asset), "seed": seed},
            )
        return asset

    def list_assets(self) -> List[str]:
        return sorted(self.assets.keys())

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        for ctx in self.assets.values():
            ctx.world.mode = mode
            ctx.governor.mode = mode
        self.audit.log("mode_changed", {"mode": mode})

    def snapshot_asset(self, key: str) -> Optional[Dict[str, Any]]:
        ctx = self.assets.get(key)
        if ctx is None:
            return None
        return {
            "asset": asdict(ctx.asset),
            "seed": ctx.seed,
            "tick": ctx.world.tick,
            "mode": ctx.world.mode,
            "world": ctx.world.to_dict(),
        }

    def tick(self, asset_key: str, scenario: str) -> TickResult:
        import time

        if asset_key not in self.assets:
            raise KeyError(f"Unknown asset: {asset_key}")

        ctx = self.assets[asset_key]
        world = ctx.world
        governor = ctx.governor
        asset = ctx.asset

        world.tick += 1
        tick_index = world.tick

        start_ns = time.perf_counter_ns()

        # 1) simulate world
        ctx.world = simulate_step(world, ctx.seed)
        world = ctx.world

        # 2) safety kernel
        risk = self.kernel.eval(world)

        # 3) governor (provisional timing)
        provisional_ms = 0.0
        decision = governor.evaluate(risk, world, provisional_ms)

        # 4) avalon oversight
        avalon_result = self.avalon.run(asset, scenario, world, risk, decision)

        end_ns = time.perf_counter_ns()
        duration_ns = end_ns - start_ns
        tick_ms = duration_ns / 1_000_000.0

        # Re-evaluate invariants with actual tick duration for logging & memory
        decision_for_log = governor.evaluate(risk, world, tick_ms)
        dec_packet = avalon_result["decision"]
        predicted_risk = float(dec_packet["predicted_risk"])
        winner_agent = str(dec_packet["winner"])

        # 5) memory frame
        frame = self.memory.add_frame(
            asset_key=asset_key,
            tick=tick_index,
            mode=world.mode,
            risk_band=risk.band,
            action=decision_for_log.action,
            invariants_violated=decision_for_log.invariants_violated,
            predicted_risk=predicted_risk,
            winner_agent=winner_agent,
            human_gate_pending=decision_for_log.requires_human_gate,
            human_gate_approved=None,
        )

        # 6) audit
        self.audit.log(
            "omega_tick",
            {
                "asset": asdict(asset),
                "asset_key": asset_key,
                "tick": tick_index,
                "duration_ms": tick_ms,
                "world": world.to_dict(),
                "risk": asdict(risk),
                "decision": asdict(decision_for_log),
                "predicted_risk": predicted_risk,
                "winner_agent": winner_agent,
                "memory_frame_id": frame.id,
            },
        )

        return TickResult(
            asset=asset,
            world=world,
            risk=risk,
            decision=decision_for_log,
            avalon=avalon_result,
            tick_ms=tick_ms,
        )

    def verify_integrity(self) -> Dict[str, Any]:
        audit_ok, audit_idx = self.audit.verify_chain()
        mem_ok, mem_idx = self.memory.verify_chain()
        return {
            "audit_ok": audit_ok,
            "audit_first_bad_index": audit_idx,
            "memory_ok": mem_ok,
            "memory_first_bad_index": mem_idx,
        }


# ============================================================================
# Streamlit UI – OmegaV2 oversight console
# ============================================================================


st.set_page_config(
    page_title="OmegaV2 – Unified Autonomous Oversight Kernel",
    layout="wide",
)


def init_session() -> None:
    if "omega" not in st.session_state:
        st.session_state.omega = OmegaV2(mode=GovernorMode.SHADOW)
        st.session_state.clarity_hist: Dict[str, List[float]] = {}
        st.session_state.risk_hist: Dict[str, List[float]] = {}
        st.session_state.pred_risk_hist: Dict[str, List[float]] = {}
        # Bootstrap a default asset
        omega: OmegaV2 = st.session_state.omega
        omega.ensure_asset("site-1", "vehicle-1")


init_session()
omega: OmegaV2 = st.session_state.omega  # type: ignore[assignment]

# --- sidebar configuration -------------------------------------------------

st.sidebar.header("OmegaV2 Configuration")

mode = st.sidebar.selectbox(
    "Governor mode (global)",
    [GovernorMode.SHADOW, GovernorMode.TRAINING, GovernorMode.LIVE],
    index=[GovernorMode.SHADOW, GovernorMode.TRAINING, GovernorMode.LIVE].index(
        omega.mode
    ),
)
if mode != omega.mode:
    omega.set_mode(mode)

st.sidebar.markdown("#### Assets")

site_input = st.sidebar.text_input("Site ID", value="site-1")
asset_input = st.sidebar.text_input("Asset ID", value="vehicle-1")
if st.sidebar.button("Ensure asset exists"):
    omega.ensure_asset(site_input.strip() or "site-1", asset_input.strip() or "vehicle-1")

asset_keys = omega.list_assets()
if not asset_keys:
    st.sidebar.warning("No assets registered yet; creating default.")
    omega.ensure_asset("site-1", "vehicle-1")
    asset_keys = omega.list_assets()

active_asset_key = st.sidebar.selectbox(
    "Active asset",
    options=asset_keys,
    index=0,
)

policy_exp = st.sidebar.expander("Active safety policy", expanded=False)
with policy_exp:
    st.code(
        json.dumps(
            {
                "id": omega.policy.id,
                "source_hash": omega.policy.source_hash,
                "risk_cfg": asdict(omega.policy.risk_cfg),
                "invariants": asdict(omega.policy.invariants),
                "band_to_action": omega.policy.band_to_action,
                "human_gate_bands_live": omega.policy.human_gate_bands_live,
                "avalon_risk_cap": omega.policy.avalon_risk_cap,
            },
            indent=2,
        ),
        language="json",
    )

st.sidebar.markdown("#### Thresholds")

risk_threshold = st.sidebar.slider("Predicted text-risk threshold (alert)", 0, 100, 60, 5)
clarity_target = st.sidebar.slider("Target clarity (%)", 0, 100, 85, 5)

st.sidebar.markdown("---")

if st.sidebar.button("Prepare audit log JSON"):
    audit_json = omega.audit.to_json()
    st.sidebar.download_button(
        label="Download omega_audit.json",
        data=audit_json,
        file_name="omega_audit.json",
        mime="application/json",
    )

if st.sidebar.button("Verify hash chains"):
    integrity = omega.verify_integrity()
    if integrity["audit_ok"] and integrity["memory_ok"]:
        st.sidebar.success("Audit and memory hash chains verified OK.")
    else:
        msg = []
        if not integrity["audit_ok"]:
            msg.append(f"Audit chain broken at index {integrity['audit_first_bad_index']}.")
        if not integrity["memory_ok"]:
            msg.append(f"Memory chain broken at index {integrity['memory_first_bad_index']}.")
        st.sidebar.error(" ".join(msg))

# --- main layout ----------------------------------------------------------

st.title("OmegaV2 – Unified Autonomous Oversight Kernel")
st.caption(
    "Multi-asset deterministic safety kernel · envelope governor · multi-agent oversight · "
    "tamper-evident audit · human-gated autonomy."
)

scenario = st.text_area(
    "Describe the system / scenario OmegaV2 is supervising.",
    height=140,
    placeholder=(
        "Example: Supervise an autonomous mining haul truck fleet under "
        "human-gated control..."
    ),
)

top_buttons = st.columns([1, 1, 6])
with top_buttons[0]:
    run_tick = st.button("Advance OmegaV2 Tick")
with top_buttons[1]:
    reset = st.button("Reset session")

if reset:
    for key in ["omega", "clarity_hist", "risk_hist", "pred_risk_hist"]:
        if key in st.session_state:
            del st.session_state[key]
    st.experimental_rerun()

if "clarity_hist" not in st.session_state:
    st.session_state.clarity_hist = {}
    st.session_state.risk_hist = {}
    st.session_state.pred_risk_hist = {}

tick_result: Optional[TickResult] = None
if run_tick and scenario.strip():
    tick_result = omega.tick(active_asset_key, scenario.strip())
    dec = tick_result.avalon["decision"]
    scores = dec["scores"]

    # Per-asset histories
    if active_asset_key not in st.session_state.clarity_hist:
        st.session_state.clarity_hist[active_asset_key] = []
        st.session_state.risk_hist[active_asset_key] = []
        st.session_state.pred_risk_hist[active_asset_key] = []

    st.session_state.clarity_hist[active_asset_key].append(scores["clarity"])
    st.session_state.risk_hist[active_asset_key].append(scores["risk"])
    st.session_state.pred_risk_hist[active_asset_key].append(dec["predicted_risk"])

# --- status bar -----------------------------------------------------------

# show active asset snapshot
snapshot = omega.snapshot_asset(active_asset_key)
if snapshot is None:
    st.error(f"Unknown asset {active_asset_key}")
    st.stop()

world_dict = snapshot["world"]
world_tick = snapshot["tick"]
world_mode = snapshot["mode"]
vehicle = world_dict["vehicle"]

status_cols = st.columns(6)
with status_cols[0]:
    st.metric("Asset", active_asset_key)
with status_cols[1]:
    st.metric("Tick", world_tick)
with status_cols[2]:
    st.metric("Mode", world_mode.upper())
with status_cols[3]:
    st.metric("Drift (deg)", f"{vehicle['drift_deg']:.1f}")
with status_cols[4]:
    st.metric("Stability", f"{vehicle['stability']:.1f}")
with status_cols[5]:
    st.metric("Speed (kph)", f"{vehicle['speed_kph']:.1f}")

st.markdown("---")

# --- panels ---------------------------------------------------------------

top_l, top_r = st.columns([1.1, 1.3])

with top_l:
    st.markdown("### Safety Envelope")

    if tick_result is not None:
        risk = tick_result.risk
        decision = tick_result.decision

        st.metric("Risk band", risk.band, help=str(risk.features))
        st.metric("Risk (0–1)", f"{risk.risk:.3f}")
        st.metric("Governor action", decision.action)

        if decision.requires_human_gate:
            st.warning(
                f"Human gate required for gate_id={decision.human_gate_id} "
                f"(band={decision.band}, mode={world_mode})."
            )
        elif risk.band in ("HOLD", "STOP"):
            st.info(
                "Envelope is in HOLD/STOP band but no live human gate required in this mode."
            )
        else:
            st.info("Risk is within configured envelopes for this mode.")
    else:
        st.info("Run at least one tick to see safety envelope metrics.")

    st.markdown("#### World snapshot (active asset)")
    st.json(world_dict)

with top_r:
    st.markdown("### Avalon Oversight & Scores")

    if tick_result is not None:
        avalon_res = tick_result.avalon
        dec = avalon_res["decision"]
        scores = dec["scores"]

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Winning agent", dec["winner"] or "N/A")
        with m2:
            st.metric("Clarity (%)", f"{scores['clarity']:.1f}")
        with m3:
            st.metric("Risk (%)", f"{scores['risk']:.1f}")
        with m4:
            st.metric("Pred. risk (%)", f"{dec["predicted_risk"]:.1f}")

        if dec["predicted_risk"] >= risk_threshold:
            st.warning(
                f"Trajectory watch: predicted risk {dec['predicted_risk']:.1f}% "
                f"≥ threshold {risk_threshold}%."
            )
        elif scores["clarity"] < clarity_target:
            st.info(
                f"Clarity {scores['clarity']:.1f}% < target {clarity_target}%. "
                "Recommend additional human review or more data."
            )
        else:
            st.success("Clarity and predicted risk are inside configured envelopes.")

        with st.expander("Winning response", expanded=True):
            st.markdown(f"**Agent:** {dec['winner'] or 'N/A'}")
            st.code(dec["response"], language="markdown")

        st.markdown("#### All agent scores (this tick)")
        score_rows: List[Dict[str, Any]] = []
        for name, sc in avalon_res["scores"].items():
            row = {"Agent": name}
            row.update(sc)
            score_rows.append(row)

        if score_rows:
            df_scores = pd.DataFrame(score_rows).sort_values("overall", ascending=False)
            st.dataframe(df_scores, use_container_width=True)
        else:
            st.info("Run at least one tick to see Avalon scores.")
    else:
        st.info("Run at least one tick to see Avalon scores.")

st.markdown("---")

mid_l, mid_r = st.columns([1.3, 1.0])

with mid_l:
    st.markdown("### Trajectory – Clarity & Risk History (active asset)")
    if (
        active_asset_key in st.session_state.clarity_hist
        and st.session_state.clarity_hist[active_asset_key]
    ):
        hist_df = pd.DataFrame(
            {
                "step": list(
                    range(1, len(st.session_state.clarity_hist[active_asset_key]) + 1)
                ),
                "Avalon clarity": st.session_state.clarity_hist[active_asset_key],
                "Avalon risk": st.session_state.risk_hist[active_asset_key],
                "Predicted risk": st.session_state.pred_risk_hist[active_asset_key],
            }
        ).set_index("step")
        st.line_chart(hist_df)
    else:
        st.caption("No history yet for this asset. Run a few ticks.")

    st.markdown("### Memory Frames (Recap Tail, active asset)")

    mem_tail = omega.memory.tail(10, asset_key=active_asset_key)
    if mem_tail:
        mem_rows = [
            {
                "id": f.id,
                "tick": f.tick,
                "mode": f.mode,
                "band": f.risk_band,
                "action": f.action,
                "pred_risk": f.predicted_risk,
                "winner": f.winner_agent,
                "gate_pending": f.human_gate_pending,
                "gate_approved": f.human_gate_approved,
                "hash": f.hash[:10] + "...",
            }
            for f in mem_tail
        ]
        st.dataframe(pd.DataFrame(mem_rows), use_container_width=True, height=260)
    else:
        st.caption("No memory frames yet for this asset.")

with mid_r:
    st.markdown("### Human Gate (Approval Log Only, active asset)")

    # We don't wire gate approval back into the world for the demo;
    # instead, we log the operator's stance into the audit spine.
    if tick_result is not None:
        decision = tick_result.decision
        if decision.requires_human_gate:
            st.markdown(f"Pending gate: **{decision.human_gate_id}**")

            approve = st.checkbox("I approve the proposed envelope action.", value=False)
            note = st.text_input("Operator note (optional):")

            if st.button("Record gate decision"):
                ctx = omega.assets[active_asset_key]
                result = ctx.governor.apply_gate(
                    decision.human_gate_id or "",
                    approved=approve,
                    operator_id="operator_anon",
                    note=note,
                )
                omega.audit.log(
                    "human_gate_decision",
                    {
                        "asset": asdict(ctx.asset),
                        "tick": decision.tick,
                        "gate_id": decision.human_gate_id,
                        "approved": approve,
                        "note": note,
                        "result": result,
                    },
                )
                st.success(
                    "Decision recorded in audit log. OmegaV2 does not actuate; this is log-only."
                )
        else:
            st.info("No human gate required for the latest tick on this asset.")
    else:
        st.caption("Run a tick to see gates.")

    st.markdown("### Audit Trail (Recent Events)")
    audit_tail = omega.audit.tail(20)
    if audit_tail:
        rows = [
            {
                "seq": e.seq,
                "ts": e.timestamp,
                "kind": e.kind,
                "hash": e.hash[:12] + "...",
                "prev_hash": e.prev_hash[:12] + "...",
            }
            for e in audit_tail
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=260)
    else:
        st.caption("No audit events yet.")

st.markdown("---")
st.caption(
    "OmegaV2 demo – single-file, deterministic oversight kernel. "
    "Extend by swapping the demo agents with real models while keeping the "
    "safety kernel, governor, audit spine, and human gate as non-negotiable rails."
)

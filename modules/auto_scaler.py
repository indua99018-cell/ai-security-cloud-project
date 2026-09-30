"""
auto_scaler.py
----------------
The decision engine. This is the piece that makes the project "security
AWARE" rather than a plain auto-scaler: scaling decisions are a function
of BOTH workload conditions and the live security/threat assessment,
not CPU alone.

Decision logic (summarized — see decide() for the exact rules):

    1. If a CRITICAL/HIGH threat is active:
         -> do NOT blindly scale up (that would reward/feed an attack,
            e.g. scaling up during a DDoS just wastes money).
         -> instead trigger mitigation (rate-limit / isolate) and hold
            or cautiously scale only enough to protect legitimate users.

    2. If traffic is clean and predicted workload is high:
         -> scale up proactively, ahead of saturation.

    3. If traffic is clean and workload is low:
         -> scale down to save cost.

    4. Otherwise: hold current capacity.

Every decision is logged with the reasoning behind it, which is what an
evaluator / SOC dashboard actually wants to see.
"""

from dataclasses import dataclass, field
from datetime import datetime


MIN_INSTANCES = 2
MAX_INSTANCES = 20

CPU_SCALE_UP_THRESHOLD = 70
CPU_SCALE_DOWN_THRESHOLD = 30


@dataclass
class ScalingDecision:
    action: str              # SCALE_UP / SCALE_DOWN / HOLD / MITIGATE
    instances_before: int
    instances_after: int
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


class AutoScaler:
    def __init__(self, initial_instances=3):
        self.current_instances = initial_instances
        self.history = []
        self.blocked_ip_pool = 0   # simulated count of mitigated/blocked sources

    def decide(self, cpu_usage, predicted_cpu, trend, threat_assessment):
        before = self.current_instances
        action = "HOLD"
        reason = "Workload and security conditions nominal — no change needed."

        threat = threat_assessment

        # --- 1. Security-aware branch: an active attack overrides normal scaling ---
        if threat.severity in ("CRITICAL", "HIGH"):
            # Simulate mitigation: block/throttle the offending traffic instead
            # of scaling resources up to absorb an attack.
            mitigated = min(50, max(5, int(threat.anomaly_score / 2)))
            self.blocked_ip_pool += mitigated

            if cpu_usage >= 85:
                # Even with mitigation, legitimate load is still critical —
                # allow a small, capped scale-up to protect real users.
                new_instances = min(self.current_instances + 1, MAX_INSTANCES)
                if new_instances != self.current_instances:
                    action = "SCALE_UP"
                    self.current_instances = new_instances
                    reason = (f"Threat={threat.severity} but legitimate load also critical "
                              f"(CPU {cpu_usage:.0f}%). Mitigated ~{mitigated} malicious sources "
                              f"AND cautiously scaled up by 1 to protect real users.")
                else:
                    action = "MITIGATE"
                    reason = (f"Threat={threat.severity}. At max capacity — relying on mitigation "
                              f"only. Blocked/throttled ~{mitigated} suspicious sources.")
            else:
                action = "MITIGATE"
                reason = (f"Threat={threat.severity} detected ({', '.join(threat.reasons[:2]) or 'anomalous pattern'}). "
                          f"Holding capacity steady and mitigating ~{mitigated} suspicious sources "
                          f"instead of rewarding the attack with more resources.")

        # --- 2. Clean traffic: normal workload-driven scaling ---
        else:
            scale_signal_up = (cpu_usage >= CPU_SCALE_UP_THRESHOLD) or \
                               (trend == "rising" and predicted_cpu >= CPU_SCALE_UP_THRESHOLD)
            scale_signal_down = (cpu_usage <= CPU_SCALE_DOWN_THRESHOLD) and \
                                 (trend != "rising") and (predicted_cpu <= CPU_SCALE_DOWN_THRESHOLD + 10)

            if scale_signal_up and self.current_instances < MAX_INSTANCES:
                step = 2 if (cpu_usage >= 85 or predicted_cpu >= 90) else 1
                new_instances = min(self.current_instances + step, MAX_INSTANCES)
                action = "SCALE_UP"
                self.current_instances = new_instances
                reason = (f"CPU {cpu_usage:.0f}% (predicted {predicted_cpu:.0f}%, trend {trend}) "
                          f"exceeds threshold. Security clear — scaling up by {step}.")

            elif scale_signal_down and self.current_instances > MIN_INSTANCES:
                new_instances = max(self.current_instances - 1, MIN_INSTANCES)
                action = "SCALE_DOWN"
                self.current_instances = new_instances
                reason = (f"CPU {cpu_usage:.0f}% (predicted {predicted_cpu:.0f}%, trend {trend}) is low "
                          f"and stable. Security clear — scaling down to cut cost.")

        decision = ScalingDecision(
            action=action,
            instances_before=before,
            instances_after=self.current_instances,
            reason=reason,
        )
        self.history.append(decision)
        return decision

    def recent_history(self, n=15):
        return self.history[-n:][::-1]

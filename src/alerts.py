import torch
import numpy as np
from src.uba import FEATURE_NAMES

# Alert levels constants
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

class AlertManager:
    def __init__(self, db_manager, evidential_model=None):
        self.db = db_manager
        self.model = evidential_model # The EvidentialNetwork PyTorch model

    def calculate_risk_level(self, threat_score, confidence_score, uncertainty_score, raw_features):
        """Classifies risk level based on threat score, uncertainty and feature severities."""
        # Check for immediate critical indicators (e.g. privilege escalation or massive tables drop)
        privileged_ops = raw_features[3]
        failed_queries = raw_features[1]
        sensitive_access = raw_features[2]

        if threat_score >= 0.8 and uncertainty_score < 0.3:
            return CRITICAL
        elif threat_score >= 0.6 and uncertainty_score < 0.4:
            return HIGH
        elif threat_score >= 0.4 or uncertainty_score >= 0.5:
            # Uncertain activities targeting sensitive tables or with high privilege ops get elevated
            if sensitive_access > 0 or privileged_ops > 0:
                return HIGH
            return MEDIUM
        elif threat_score >= 0.2:
            return LOW
        else:
            return LOW

    def get_remediation_action(self, username, risk_level, top_features):
        """Returns recommended action based on risk level and contributing features."""
        actions = []
        if risk_level == CRITICAL:
            actions.append(f"IMMEDIATE ACTION: Temporarily lock database user account '{username}'.")
            actions.append("Terminate active database connection sessions.")
            actions.append("Initiate full incident response and forensic database audit.")
        elif risk_level == HIGH:
            if "privileged_op_count" in top_features or "sensitive_access_count" in top_features:
                actions.append(f"Revoke administrative/modification permissions for '{username}' immediately.")
            actions.append(f"Alert Security Operations Center (SOC) and request multi-factor authentication (MFA) re-verification.")
            actions.append("Monitor all queries for the next 24 hours.")
        elif risk_level == MEDIUM:
            if "failed_query_count" in top_features:
                actions.append("Inspect client IP address for potential brute-force or query script issues.")
            actions.append(f"Log alert, send to manual compliance review, and notify database administrator.")
        else:
            actions.append("Log for compliance correlation. No immediate action required.")
            
        return "\n".join([f"- {a}" for a in actions])

    def explain_anomaly(self, raw_features, normalized_features, username):
        """Computes feature contributions to explain why the model flagged this session.
        Uses a combination of Z-score deviation (from profiles) and PyTorch backpropagation
        gradients (model saliency) to identify which features drove the anomaly score.
        """
        # 1. Z-Score Deviation (Statistical)
        deviations = {}
        for idx, name in enumerate(FEATURE_NAMES):
            z_val = normalized_features[idx]
            raw_val = raw_features[idx]
            
            # Translate raw values for cleaner display
            if name == "log_bytes_returned":
                # Convert back from log scale for readability
                display_val = f"{int(np.expm1(raw_val))} bytes"
            elif name in ["off_hours_ratio", "select_ratio"]:
                display_val = f"{raw_val * 100:.1f}%"
            else:
                display_val = f"{int(raw_val)}"
                
            deviations[name] = {
                "z_score": z_val,
                "raw_val": display_val,
                "importance": 0.0 # Will be populated by model gradients
            }

        # 2. PyTorch Gradient Saliency (Neural network feature attribution)
        if self.model:
            self.model.eval()
            
            # Convert normalized features to PyTorch tensor with gradient tracking
            z_tensor = torch.tensor(normalized_features, dtype=torch.float32).unsqueeze(0)
            z_tensor.requires_grad = True
            
            try:
                # Forward pass
                evidence = self.model(z_tensor)
                alpha = evidence + 1.0
                S = torch.sum(alpha, dim=1)
                
                # We calculate gradient with respect to Threat Score: alpha_1 / S
                threat_score = alpha[0, 1] / S[0]
                
                # Backward pass
                threat_score.backward()
                
                # The gradient shows how sensitive the Threat Score is to changes in each feature
                # Saliency is the absolute product of gradient and features: |gradient * feature|
                gradients = z_tensor.grad.squeeze().numpy()
                saliency = np.abs(gradients * normalized_features)
                
                # Normalize saliency to percentages
                total_saliency = np.sum(saliency)
                if total_saliency > 0:
                    saliency_pct = (saliency / total_saliency) * 100
                else:
                    saliency_pct = np.zeros_like(saliency)
                    
                for idx, name in enumerate(FEATURE_NAMES):
                    deviations[name]["importance"] = float(saliency_pct[idx])
            except Exception as e:
                # Fallback if gradient calculation fails (e.g. no PyTorch graph)
                pass

        # Sort features by neural network importance, falling back to Z-score absolute value
        sorted_features = sorted(
            deviations.items(),
            key=lambda x: (x[1]["importance"], abs(x[1]["z_score"])),
            reverse=True
        )
        
        return sorted_features

    def process_and_alert(self, username, raw_features, normalized_features, prediction):
        """Generates an alert, logs it in the database, and returns it."""
        threat_score = prediction["threat_score"]
        confidence_score = prediction["confidence_score"]
        uncertainty_score = prediction["uncertainty_score"]
        decision = prediction["decision"]
        
        # Calculate risk level
        risk_level = self.calculate_risk_level(threat_score, confidence_score, uncertainty_score, raw_features)
        
        # Generate feature explanation
        explanation_details = self.explain_anomaly(raw_features, normalized_features, username)
        
        # Format explanation text and retrieve top features
        top_features = []
        explanation_lines = []
        explanation_lines.append(f"Model Decision: {decision}")
        explanation_lines.append(f"Uncertainty: {uncertainty_score:.2f} (Confidence: {confidence_score:.2f})")
        explanation_lines.append("\nTop Feature Contributions:")
        
        for name, details in explanation_details[:3]:
            top_features.append(name)
            z_str = f"+{details['z_score']:.1f}" if details['z_score'] >= 0 else f"{details['z_score']:.1f}"
            importance_str = f" [Contrib: {details['importance']:.1f}%]" if details['importance'] > 0 else ""
            explanation_lines.append(
                f"- {name}: Value = {details['raw_val']} ({z_str} Std Devs from baseline){importance_str}"
            )
            
        explanation_text = "\n".join(explanation_lines)
        
        # Generate threat description
        description = ""
        if decision == "High-Confidence Threat":
            description = f"High-confidence threat behavior detected for user '{username}'. "
            if "privileged_op_count" in top_features:
                description += "Suspicious administrative or privilege modifications were attempted."
            elif "sensitive_access_count" in top_features:
                description += "Unauthorized access or querying of sensitive data tables detected."
            elif "log_bytes_returned" in top_features:
                description += "Abnormal data volume retrieved, indicating mass data extraction."
            else:
                description += "General user query behavior deviated drastically from historical profiles."
        elif decision == "Uncertain Activity":
            description = f"Suspicious activity with high predictive uncertainty for user '{username}'. Manual review is recommended."
        else:
            description = f"Normal baseline activity observed for user '{username}'."
            
        recommended_action = self.get_remediation_action(username, risk_level, top_features)
        
        # Save alert to database if it is not normal or if it is suspicious
        alert_id = None
        if decision in ["High-Confidence Threat", "Uncertain Activity"] or risk_level in [MEDIUM, HIGH, CRITICAL]:
            alert_id = self.db.insert_alert(
                username=username,
                threat_score=threat_score,
                confidence_score=confidence_score,
                uncertainty_score=uncertainty_score,
                alert_level=risk_level,
                description=description,
                explanation=explanation_text,
                recommended_action=recommended_action
            )
            
        return {
            "id": alert_id,
            "username": username,
            "threat_score": threat_score,
            "confidence_score": confidence_score,
            "uncertainty_score": uncertainty_score,
            "alert_level": risk_level,
            "description": description,
            "explanation": explanation_text,
            "recommended_action": recommended_action,
            "decision": decision
        }

    @staticmethod
    def format_alert_cli(alert):
        """Formats alert into a beautiful console card with ANSI colors."""
        # Setup colors
        colors = {
            "CRITICAL": "\033[91;1m", # Bright red
            "HIGH": "\033[91m",     # Red
            "MEDIUM": "\033[93m",   # Yellow
            "LOW": "\033[94m",      # Blue
            "RESET": "\033[0m",
            "CYAN": "\033[96m",
            "WHITE_BOLD": "\033[97;1m"
        }
        
        lvl = alert["alert_level"]
        c_lvl = colors.get(lvl, colors["RESET"])
        c_reset = colors["RESET"]
        c_cyan = colors["CYAN"]
        
        border = f"{c_lvl}{'='*60}{c_reset}"
        
        card = [
            border,
            f"{colors['WHITE_BOLD']}DATABASE SECURITY ALERT #{alert.get('id', 'N/A')}{c_reset}",
            f"Risk Level:  {c_lvl}{lvl}{c_reset}",
            f"User:        {colors['WHITE_BOLD']}{alert['username']}{c_reset}",
            f"Decision:    {alert['decision']}",
            f"Threat Score: {c_lvl}{alert['threat_score']:.4f}{c_reset} | Confidence: {alert['confidence_score']:.4f} | Uncertainty: {alert['uncertainty_score']:.4f}",
            border,
            f"{c_cyan}Description:{c_reset}\n{alert['description']}",
            f"\n{c_cyan}Explainability Details:{c_reset}\n{alert['explanation']}",
            f"\n{c_cyan}Remediation Recommendations:{c_reset}\n{alert['recommended_action']}",
            border
        ]
        return "\n".join(card)

import re
import pickle
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
from scipy.sparse import hstack, csr_matrix
from config import settings

URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "action required", "account suspended",
    "within 24 hours", "terminate", "verify password", "unauthorized login",
    "wire transfer", "confidential", "critical security alert", "expires today",
    "direct deposit", "unclaimed refund", "security advisory alert"
]

GENERIC_GREETINGS = [
    "dear valued user", "dear customer", "dear client", "hello user", "dear member"
]


class RiskClassifier:
    """
    Step 8: AI/ML Risk Classifier.
    Combines NLP text features (TF-IDF + urgency words + generic greetings + link mismatches)
    with structural features (SPF, DKIM, DMARC, WHOIS domain age, threat reputation score,
    dangerous attachments). Predicts phishing probability with scikit-learn.
    """

    def __init__(self, model_path: Path = settings.MODEL_PATH):
        self.model_path = model_path
        self.model_bundle = self._load_or_train_model()

    def _load_or_train_model(self) -> Dict[str, Any]:
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    return pickle.load(f)
            except Exception:
                pass

        # If model doesn't exist yet, run automated training
        try:
            from ml.train import train_model
            return train_model(str(self.model_path))
        except Exception as e:
            # Fallback if scikit-learn is still installing
            return {"vectorizer": None, "classifier": None, "error": str(e)}

    def classify(self, parsed_email: Dict[str, Any], auth_results: Dict[str, Any],
                 whois_data: Dict[str, Any], threat_intel: Dict[str, Any]) -> Dict[str, Any]:

        subject = parsed_email.get("headers", {}).get("subject", "")
        body_text = parsed_email.get("body", {}).get("text", "")
        combined_text = f"{subject} {body_text}".lower()

        # 1. NLP Heuristic Features
        urgency_matches = [w for w in URGENCY_KEYWORDS if w in combined_text]
        generic_greeting_detected = any(g in combined_text for g in GENERIC_GREETINGS)
        mismatched_links = parsed_email.get("urls", {}).get("mismatched_links", [])
        has_mismatch = 1 if len(mismatched_links) > 0 else 0

        # Attachments check
        attachments = parsed_email.get("attachments", [])
        has_dangerous_att = 1 if any(a.get("is_dangerous", False) for a in attachments) else 0

        # 2. Structural Features
        spf_pass = 1 if auth_results.get("spf", {}).get("status") == "pass" else 0
        dkim_pass = 1 if auth_results.get("dkim", {}).get("status") == "pass" else 0
        dmarc_pass = 1 if auth_results.get("dmarc", {}).get("status") in ("pass", "policy_present") else 0
        is_young = 1 if whois_data.get("is_young", False) else 0
        rep_score = threat_intel.get("threat_risk_score", 0)

        # 3. Predict with ML model if loaded
        clf = self.model_bundle.get("classifier")
        vec = self.model_bundle.get("vectorizer")

        explanations: List[str] = []

        if clf and vec:
            X_text = vec.transform([combined_text])
            X_struct = csr_matrix(np.array([[
                spf_pass, dkim_pass, dmarc_pass, is_young,
                rep_score / 100.0, has_mismatch, has_dangerous_att
            ]]))
            X_all = hstack([X_text, X_struct])

            # Predict probability of phishing (class 1)
            probs = clf.predict_proba(X_all)[0]
            ml_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            ml_score = round(ml_prob * 100.0, 1)
        else:
            # Fallback heuristic calculation if ML libraries pending
            base_score = 10.0
            if not spf_pass:
                base_score += 25.0
            if is_young:
                base_score += 20.0
            if has_mismatch:
                base_score += 20.0
            if len(urgency_matches) > 0:
                base_score += min(25.0, len(urgency_matches) * 10.0)
            if rep_score > 30:
                base_score += 20.0
            ml_score = min(100.0, base_score)

        # Generate human-readable AI feature explanations
        if urgency_matches:
            explanations.append(f"High urgency phrasing detected: '{', '.join(urgency_matches[:3])}'")
        if generic_greeting_detected:
            explanations.append("Generic impersonal greeting pattern identified.")
        if has_mismatch:
            explanations.append(f"Deceptive hyperlink detected (anchor text does not match actual destination).")
        if not spf_pass:
            explanations.append("Sender failed SPF domain authorization.")
        if is_young:
            explanations.append(f"Domain registered recently (<30 days old: {whois_data.get('age_days', 0)} days).")
        if rep_score >= 50:
            explanations.append(f"Threat intelligence flagged origin IP or links (Reputation Risk: {rep_score}/100).")
        if has_dangerous_att:
            explanations.append("Suspicious executable or script attachment detected.")

        if not explanations:
            explanations.append("No abnormal NLP or structural threat indicators found. Normal correspondence characteristics.")

        return {
            "ml_risk_score": ml_score,
            "urgency_keywords_found": urgency_matches,
            "generic_greeting": generic_greeting_detected,
            "mismatched_links_count": len(mismatched_links),
            "dangerous_attachments_count": sum(1 for a in attachments if a.get("is_dangerous", False)),
            "model_type": "RandomForest (NLP TF-IDF + Structural Forensics)" if clf else "Heuristic Fallback",
            "explanations": explanations
        }

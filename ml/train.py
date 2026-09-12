import sys
import pickle
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
packages_dir = BASE_DIR / "packages"
if packages_dir.exists() and str(packages_dir) not in sys.path:
    sys.path.insert(0, str(packages_dir))

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from scipy.sparse import hstack, csr_matrix

# Representative dataset of clean and phishing/spoofed emails
TRAINING_DATA = [
    # Clean emails (label = 0)
    {
        "text": "Hi team, please find attached the updated minutes from our weekly architecture sync. Let me know if any corrections are needed before our standup tomorrow.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "Your Amazon order #402-98124 has shipped! Track your package on your dashboard or via the carrier tracking link provided.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "GitHub notification: Dependabot alerts resolved in repository. Build passed on main branch with 100% test coverage.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "Quarterly financial summary report. All department heads should review budget allocations for Q3 planning meeting next Thursday.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "Welcome to our newsletter! Here are this month's top open-source security engineering articles, tutorials, and vulnerability disclosures.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "Invoice #8912 for cloud hosting services attached for your records. Payment has already been received via corporate card on file.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "Sprint retrospective calendar invitation: Monday at 10:00 AM UTC. Please review the Kanban board before joining.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },
    {
        "text": "Your flight itinerary confirmation. Terminal 2 departure at 14:30. Check-in online 24 hours prior to departure.",
        "spf_pass": 1, "dkim_pass": 1, "dmarc_pass": 1, "is_young": 0, "rep_score": 0, "has_mismatch": 0, "has_dangerous_att": 0, "label": 0
    },

    # Phishing & Malicious emails (label = 1)
    {
        "text": "URGENT: Critical Security Alert! Dear Valued User, your corporate mailbox will be suspended within 24 hours unless you verify password immediately. Click here to confirm identity.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 85, "has_mismatch": 1, "has_dangerous_att": 0, "label": 1
    },
    {
        "text": "Confidential: Immediate Wire Transfer Request from CEO. Process payment of $95,000 to offshore escrow account before 4 PM today. Do not discuss with anyone.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 75, "has_mismatch": 0, "has_dangerous_att": 0, "label": 1
    },
    {
        "text": "Your account has been temporarily locked due to suspicious activity. Verify your billing credentials and credit card information to restore access.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 90, "has_mismatch": 1, "has_dangerous_att": 0, "label": 1
    },
    {
        "text": "Payment Overdue: Please open the attached remittance invoice document payment_advice.iso immediately to prevent legal collections action.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 0, "rep_score": 60, "has_mismatch": 0, "has_dangerous_att": 1, "label": 1
    },
    {
        "text": "Microsoft 365 Password Expiration Notice. Your password expires today. Update password now or lose access to all corporate OneDrive files.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 80, "has_mismatch": 1, "has_dangerous_att": 0, "label": 1
    },
    {
        "text": "Payroll update required: Direct deposit failure. Update your bank account routing number immediately via employee portal link.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 70, "has_mismatch": 1, "has_dangerous_att": 0, "label": 1
    },
    {
        "text": "IRS Tax Refund Notice: You have an unclaimed tax refund of $1,420. Download attached claim form refund_form.exe and submit within 48 hours.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 95, "has_mismatch": 1, "has_dangerous_att": 1, "label": 1
    },
    {
        "text": "DocuSign: Action Required. Please review and sign the attached legal settlement document before expiration. Click review document.",
        "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "is_young": 1, "rep_score": 65, "has_mismatch": 1, "has_dangerous_att": 0, "label": 1
    }
]


def extract_structural_features(data_point: dict) -> list:
    return [
        data_point.get("spf_pass", 0),
        data_point.get("dkim_pass", 0),
        data_point.get("dmarc_pass", 0),
        data_point.get("is_young", 0),
        data_point.get("rep_score", 0) / 100.0,
        data_point.get("has_mismatch", 0),
        data_point.get("has_dangerous_att", 0)
    ]


def train_model(save_path: str = "ml/model.pkl"):
    texts = [d["text"] for d in TRAINING_DATA]
    y = np.array([d["label"] for d in TRAINING_DATA])

    # 1. TF-IDF vectorizer for NLP features
    vectorizer = TfidfVectorizer(
        max_features=500,
        stop_words="english",
        ngram_range=(1, 2)
    )
    X_tfidf = vectorizer.fit_transform(texts)

    # 2. Structural features matrix
    structural_features = np.array([extract_structural_features(d) for d in TRAINING_DATA])
    X_struct = csr_matrix(structural_features)

    # 3. Stack text + structural features
    X_combined = hstack([X_tfidf, X_struct])

    # 4. Train RandomForest classifier
    clf = RandomForestClassifier(
        n_estimators=50,
        max_depth=6,
        random_state=42
    )
    clf.fit(X_combined, y)

    # 5. Save model bundle
    bundle = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "feature_names": vectorizer.get_feature_names_out().tolist() + [
            "feat_spf_pass", "feat_dkim_pass", "feat_dmarc_pass",
            "feat_is_young_domain", "feat_rep_score",
            "feat_mismatched_links", "feat_dangerous_att"
        ]
    }

    out_file = Path(save_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "wb") as f:
        pickle.dump(bundle, f)

    print(f"[SecureX ML] Trained and serialized model to {out_file.resolve()}")
    return bundle


if __name__ == "__main__":
    train_model()

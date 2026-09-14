# Incident: ML Model Artifact Missing, Corrupted, or Inference Failure

## Purpose

Operational recovery procedure when the machine learning risk classifier bundle (`ml/model.pkl`) is missing, corrupted, unpicklable due to dependency mismatch, or throwing inference exceptions.

## Impact

- Stage 8 ML Risk Classification in the pipeline fails or falls back to degraded heuristic defaults.
- Composite risk scoring lacks machine-learned NLP and structural probability weights, relying solely on rule-based heuristics.
- Logs report unpickling warnings, `AttributeError`, or `ModuleNotFoundError` during classification.

## Symptoms

- Server logs display:
  - `AttributeError: Can't get attribute '...' on <module '...'>`
  - `_pickle.UnpicklingError: invalid load key`
  - `InconsistentVersionWarning: Trying to unpickle estimator ... from version ... when using version ...`
  - `[RiskClassifier] Automated model training failed: ...`
- Model file `ml/model.pkl` is 0 bytes or does not exist on disk.
- Endpoint `/api/analyze` logs warnings about ML fallback mode.

## Severity

**P1 — Service Degradation (Pipeline Operating in Fallback Mode)**

## Immediate Actions

1. Check if the model file exists and examine its size:
   ```bash
   ls -lh ml/model.pkl
   ```
   - Normal size is typically between 50KB and 5MB.
   - If file size is 0 bytes, the artifact is broken.
2. Test if Python can load the pickled model:
   ```bash
   python3 -c "
   import pickle
   from config import settings
   with open(settings.MODEL_PATH, 'rb') as f:
       bundle = pickle.load(f)
   print('Model loaded successfully. Keys:', list(bundle.keys()))
   "
   ```

## Diagnosis

### Step 1: Check Scikit-Learn Version Compatibility
Pickle files are sensitive to Python and `scikit-learn` versions. If the model was trained under scikit-learn 1.3 and executed under 1.4+, unpickling may fail:
```bash
python3 -c "import sklearn; print('Installed scikit-learn version:', sklearn.__version__)"
```

### Step 2: Check File Permissions on `ml/` Directory
The application needs read access to `ml/model.pkl` and write access if retraining:
```bash
ls -ld ml/ ml/model.pkl
```

### Step 3: Test Model Inference Dry-Run
Execute a standalone test using the classifier engine:
```bash
python3 -c "
from core.classifier import RiskClassifier
clf = RiskClassifier()
res = clf.classify(
    parsed_email={'headers': {'subject': 'Urgent verification'}, 'body': {'text': 'Verify your account'}},
    auth_results={'spf': {'status': 'fail'}},
    whois_data={'domain_age_days': 2},
    threat_intel={}
)
print('Inference output:', res)
"
```
Expected output: A dictionary containing `ml_phishing_probability`, `predicted_label`, and `urgency_detected`.

## Recovery

### Scenario A: Retraining the Model Artifact (SAFE AUTOMATION)
The repository includes a self-contained training script (`ml/train.py`) that generates the model artifact deterministically:
1. Re-run training in the current environment:
   ```bash
   python3 ml/train.py
   ```
2. Verify the new model artifact was generated:
   ```bash
   ls -lh ml/model.pkl
   ```
3. Restart the application or container to reload the model into memory:
   ```bash
   # Docker:
   docker compose restart mailguardian
   # Host:
   pkill -f "uvicorn.*app:app" && python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 &
   ```

### Scenario B: Rebuilding the Docker Image with Pre-Trained Model (SAFE AUTOMATION)
The project's `Dockerfile` runs `RUN python ml/train.py` during build time. If running in Docker:
```bash
docker compose build mailguardian
docker compose up -d mailguardian
```

### Scenario C: Scikit-Learn Package Mismatch (REQUIRES HUMAN APPROVAL)
If pip dependencies are out of sync with `requirements.txt`:
```bash
pip install -r requirements.txt --upgrade
python3 ml/train.py
```

## Validation

1. Verify `ml/model.pkl` exists with non-zero size:
   ```bash
   test -s ml/model.pkl && echo "Model file: OK" || echo "Model file: BROKEN"
   ```
2. Run the integration test suite to verify ML classification:
   ```bash
   PYTHONPATH=packages:. python3 -m unittest discover -s tests -v
   ```
   Expected output: All unit tests pass (`OK`).
3. Run a test sample through the API:
   ```bash
   curl -s http://127.0.0.1:8000/api/sample/phishing | python3 -c "
   import sys, json
   res = json.load(sys.stdin)
   print('Classifier verdict:', res.get('classifier', {}).get('predicted_label'))
   print('Phishing probability:', res.get('classifier', {}).get('ml_phishing_probability'))
   "
   ```
   Expected output: `predicted_label: Malicious` or `Suspicious`.

## Rollback

- If retraining produces an unexpected model behavior:
  - Revert `ml/model.pkl` from git if tracked, or rerun `python3 ml/train.py` with default seed.
  - If no previous model exists:
    "No verified model version archive found; retrain using `python3 ml/train.py`."

## Escalation

- Escalate to Machine Learning / Data Science Lead if:
  - Synthetic training dataset in `ml/train.py` fails to converge or throws shape mismatch errors.
  - Feature matrix dimension mismatch between `core/classifier.py` and `ml/train.py`.

## Do Not

- **DO NOT** commit random third-party `.pkl` files from untrusted sources (potential arbitrary code execution vulnerability via pickle).
- **DO NOT** disable classifier error handling in `core/pipeline.py`.
- **DO NOT** delete `ml/train.py`.

## Root Cause Follow-Up

1. Verify that `requirements.txt` specifies fixed versions for `scikit-learn` and `numpy` to prevent incompatible upgrades during container builds.
2. Ensure Docker volume mounts do not overwrite `/app/ml` with an empty host folder.

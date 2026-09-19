# Commerce Sentinel model contract

The gateway currently falls back to signature rules because no newly trained commerce model has been supplied.

Export a binary XGBoost Booster using `booster.save_model("xgb.json")` into this directory. Feature order and names must exactly match `features.json`, objective must be `binary:logistic`, and output is the attack probability. Set class 0 = normal and class 1 = suspicious. Train with exactly the transformations in `services/commerce/detection.py`. SOC events include the feature values and versioned contract can be used for dataset creation. This repository does not claim that AI-generated labels are ground truth.

Do not copy the legacy `tfidf.pkl` or `scaler.pkl` into this deployment. They require unsafe pickle deserialization and an incompatible feature pipeline. An absent, incompatible, failing, busy or timed-out model uses rules; SOC explicitly distinguishes rule score from model probability. Inference has one in-flight worker and a 150 ms response deadline. A timed-out native inference may finish later but does not spawn additional workers.

The 0.7 model threshold and signature scores are configuration/design defaults, not validated accuracy claims. Calibrate the classifier on held-out normal shopping traffic and attack sequences before presenting accuracy or false-positive claims.

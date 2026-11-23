import random
from urllib.parse import urlsplit

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit

from feature_extraction import FeatureExtractor

# 1. Load the data
df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
df = df.drop_duplicates(subset="URL")

# 2. In this dataset label 0 = phishing. We want 1 = phishing.
y = (df["label"] == 0).astype(int)

# 3. Turn every URL into numbers
fx = FeatureExtractor()
print("Extracting features (about a minute)...")
X = pd.DataFrame([fx.extract(url) for url in df["URL"]])
print("Feature table:", X.shape)


# 4. Split into training and test data, keeping each website on one side only
def site_name(url):
    host = (urlsplit(url).hostname or "").split(".")
    return ".".join(host[-2:])


groups = [site_name(u) for u in df["URL"]]
splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

# 4b. Add variety to the LEGITIMATE websites (training data only, never the test data)
SUBDOMAINS = ["en", "blog", "docs", "support", "shop", "news", "app", "help",
              "store", "m", "mail", "accounts", "developer", "community", "portal"]


def make_variant(url, rng):
    parts = urlsplit(url)
    host = parts.netloc
    if host.startswith("www.") and rng.random() < 0.4:
        host = host[4:]
    if rng.random() < 0.25:
        host = rng.choice(SUBDOMAINS) + "." + host
    return f"{parts.scheme}://{host}"


rng = random.Random(11)
all_urls = df["URL"].tolist()
legit_train_urls = [all_urls[i] for i in train_idx if y.iloc[i] == 0]
X_extra = pd.DataFrame([fx.extract(make_variant(u, rng)) for u in legit_train_urls])
X_train = pd.concat([X_train, X_extra], ignore_index=True)
y_train = pd.concat([y_train, pd.Series([0] * len(X_extra))], ignore_index=True)
print("Training rows after adding variety:", len(X_train))

# 5. Train
print("Training...")
model = RandomForestClassifier(n_estimators=100, min_samples_leaf=2,
                               class_weight="balanced", n_jobs=-1, random_state=42)
model.fit(X_train, y_train)

# 6. Check how good it is on websites it has never seen
pred = model.predict(X_test)
print(classification_report(y_test, pred, target_names=["legitimate", "phishing"]))
print(confusion_matrix(y_test, pred))

# 7. Save
joblib.dump({"model": model, "features": list(X.columns)}, "phish_model.joblib")
print("Saved phish_model.joblib")
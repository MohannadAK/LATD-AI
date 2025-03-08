import pandas as pd
import numpy as np
import kagglehub
from kagglehub import KaggleDatasetAdapter
from sklearn.preprocessing import MaxAbsScaler, RobustScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.decomposition import PCA
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, make_scorer, precision_recall_curve
from sklearn.metrics import confusion_matrix, matthews_corrcoef
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.feature_selection import SelectKBest, f_classif
from imblearn.over_sampling import SMOTE
from itertools import combinations
import logging
import os
import datetime


def verify_csv(file_path):
    import csv
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            csv.Sniffer().sniff(f.read(1024))  # Check the first 1KB for CSV structure
            f.seek(0)
            reader = csv.reader(f)
            next(reader)  # Check if header exists
        print(f"{file_path} appears to be a valid CSV.")
    except Exception as e:
        print(f"{file_path} may be corrupted: {e}")
        raise


def download_unsw_nb15(dataset_folder="../dataset/UNSW_NB15"):
    """Download the UNSW-NB15 dataset using KaggleHub if it doesn't exist."""
    import os
    os.makedirs(dataset_folder, exist_ok=True)

    train_file = os.path.join(dataset_folder, "UNSW_NB15_training-set.csv")
    test_file = os.path.join(dataset_folder, "UNSW_NB15_testing-set.csv")

    if os.path.exists(train_file) and os.path.exists(test_file):
        print("Dataset already exists. Skipping download.")
        return

    print("Downloading UNSW-NB15 dataset using KaggleHub...")

    # Define the dataset handle
    dataset_handle = "mrwellsdavid/unsw-nb15"

    # Download the dataset
    path = kagglehub.dataset_download(dataset_handle, path=None)  # Downloads the entire dataset

    # Since dataset_download returns a directory, we need to move the specific files
    import shutil
    for file_name in os.listdir(path):
        if "training-set" in file_name:
            shutil.move(os.path.join(path, file_name), train_file)
        elif "testing-set" in file_name:
            shutil.move(os.path.join(path, file_name), test_file)

    print("Dataset downloaded and saved successfully!")

    verify_csv(train_file)
    verify_csv(test_file)


def setup_logging():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = "log_archive"

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f"{timestamp}_suspicious_logs.log")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=log_file,
        filemode='w'
    )
    return log_file

def custom_scorer(y_true, y_pred):
    f1 = f1_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    return (f1 + recall) / 2

def load_unsw_nb15(filepath):
    print(f"Loading data from {filepath}...")
    try:
        # Use Python engine for more robust parsing
        df = pd.read_csv(
            filepath,
            low_memory=False,
            encoding='utf-8',
            na_values=['-'],
            engine='python',  # More forgiving than the default 'c' engine
            on_bad_lines='warn'  # Warn about bad lines instead of raising an error
        )

        if 'label' in df.columns:
            X = df.drop(['label'], axis=1)
            y = df['label']
        elif 'attack_cat' in df.columns:
            df['label'] = df['attack_cat'].notna().astype(int)
            X = df.drop(['label', 'attack_cat'], axis=1)
            y = df['label']
        else:
            raise ValueError("No suitable label column found.")

        numeric_features = X.select_dtypes(include=['int64', 'float64']).columns
        categorical_features = ['state', 'service']

        if 'timestamp' in X.columns:
            X['timestamp'] = pd.to_datetime(X['timestamp'], errors='coerce')
            X['hour'] = X['timestamp'].dt.hour
            X['day_of_week'] = X['timestamp'].dt.dayofweek
            numeric_features = numeric_features.union(pd.Index(['hour', 'day_of_week']))
            X = X.drop('timestamp', axis=1)

        return X, y, numeric_features, categorical_features
    except Exception as e:
        print(f"Failed to load {filepath}: {e}")
        raise

def preprocess_data(X, numeric_features, categorical_features, n_components=0.95):
    numeric_transformer = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', RobustScaler()),
        ('maxabs', MaxAbsScaler())
    ])

    categorical_transformer = Pipeline([
        ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])

    preprocessor = ColumnTransformer([
        ('num', numeric_transformer, numeric_features),
        ('cat', categorical_transformer, categorical_features)
    ])

    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('pca', PCA(n_components=n_components))
    ])

    X_processed = pipeline.fit_transform(X)
    return X_processed, pipeline


def select_features(X, y, feature_names, k=20):
    selector = SelectKBest(score_func=f_classif, k=k)
    X_selected = selector.fit_transform(X, y)
    feature_names = np.array(feature_names)
    selected_features = feature_names[selector.get_support()]
    return X_selected, selected_features


def train_supervised_model(X_train, y_train):
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10],
        'class_weight': ['balanced', None]
    }

    clf = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(
        estimator=clf,
        param_grid=param_grid,
        cv=StratifiedKFold(n_splits=3),
        n_jobs=-1,
        verbose=2,
        scoring=make_scorer(custom_scorer)
    )
    grid_search.fit(X_train, y_train)

    print("Best parameters:", grid_search.best_params_)
    return grid_search.best_estimator_

def train_anomaly_detector(X_train, contamination='auto'):
    iso_forest = IsolationForest(contamination=contamination, random_state=42)
    iso_forest.fit(X_train)
    return iso_forest

def find_optimal_threshold(model, X_val, y_val):
    probs = model.predict_proba(X_val)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_val, probs)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    optimal_threshold = thresholds[np.argmax(f1_scores)]
    return optimal_threshold

def evaluate_model(y_true, y_pred, X_test, model, feature_names, log_file, sample_rate=0.1):
    cv = StratifiedKFold(n_splits=5)
    cv_scores = cross_val_score(model, X_test, y_true, cv=cv, scoring='f1')
    print(f"Cross-validation F1 scores: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    f1 = f1_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_pred)
    mcc = matthews_corrcoef(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)

    print("\nConfusion Matrix:")
    print(cm)

    suspicious_indices = np.where(y_pred == 1)[0]
    if len(suspicious_indices) > 0:
        sample_size = max(1, int(len(suspicious_indices) * sample_rate))
        sampled_indices = np.random.choice(suspicious_indices, size=sample_size, replace=False)
        for index in sampled_indices:
            log_entry = X_test.iloc[index].to_dict()
            log_entry['true_label'] = y_true.iloc[index]
            log_entry['predicted_label'] = y_pred[index]
            logging.info(f"Suspicious log detected: {log_entry}")

    return {
        'F-score': f1,
        'Precision': precision,
        'Recall': recall,
        'AUC-ROC': auc,
        'MCC': mcc
    }

def feature_interaction(X, feature_names, top_features=5):
    top_feature_names = feature_names[:top_features]
    interactions = []
    for feat1, feat2 in combinations(top_feature_names, 2):
        interaction_name = f"{feat1}_{feat2}_interaction"
        interaction_value = X[feat1] * X[feat2]
        interactions.append((interaction_name, interaction_value))

    interactions_df = pd.DataFrame(dict(interactions), index=X.index)
    return interactions_df

if __name__ == "__main__":
    download_unsw_nb15()
    dataset_folder = "dataset/UNSW_NB15"
    train_filepath = f"../{dataset_folder}/UNSW_NB15_training-set.csv"
    test_filepath = f"../{dataset_folder}/UNSW_NB15_testing-set.csv"

    log_file = setup_logging()

    try:
        X_train, y_train, numeric_features, categorical_features = load_unsw_nb15(train_filepath)
        X_test, y_test, _, _ = load_unsw_nb15(test_filepath)

        X_train_processed, preprocessor = preprocess_data(
            X_train, numeric_features, categorical_features, n_components=0.95
        )
        X_test_processed = preprocessor.transform(X_test)

        n_components = X_train_processed.shape[1]
        pca_feature_names = [f"PC{i+1}" for i in range(n_components)]

        X_train_df = pd.DataFrame(X_train_processed, columns=pca_feature_names, index=X_train.index)
        X_test_df = pd.DataFrame(X_test_processed, columns=pca_feature_names, index=X_test.index)

        X_train_selected, selected_features = select_features(
            X_train_df, y_train, pca_feature_names, k=min(20, n_components)  # Ensure k does not exceed n_components
        )
        X_test_selected = X_test_df[selected_features]

        supervised_model = train_supervised_model(X_train_selected, y_train)
        anomaly_detector = train_anomaly_detector(
            X_train_selected[y_train == 0], contamination='auto'
        )

        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train_selected, y_train, test_size=0.2, stratify=y_train, random_state=42
        )
        supervised_model.fit(X_train_split, y_train_split)
        optimal_threshold = find_optimal_threshold(supervised_model, X_val, y_val)
        print(f"Optimal threshold: {optimal_threshold:.4f}")

        probs = supervised_model.predict_proba(X_test_selected)[:, 1]
        supervised_preds = (probs >= optimal_threshold).astype(int)

        anomaly_preds = anomaly_detector.predict(X_test_selected)
        anomaly_preds = np.where(anomaly_preds == -1, 1, 0)

        final_preds = np.where(supervised_preds == 1, 1, anomaly_preds)

        results = evaluate_model(
            y_test, final_preds, X_test_df, supervised_model, selected_features, log_file, sample_rate=0.1
        )
        print("\nInitial Model Results:")
        print(results)

        importances = supervised_model.feature_importances_
        feature_importance = pd.DataFrame({
            'feature': selected_features,
            'importance': importances
        })
        feature_importance = feature_importance.sort_values('importance', ascending=False)
        print("\nTop 10 Feature Importances:")
        print(feature_importance.head(10))

        interactions_df = feature_interaction(X_train_df, selected_features, top_features=5)

        X_train_with_interactions = pd.concat([X_train_df, interactions_df], axis=1)
        X_test_with_interactions = pd.concat(
            [X_test_df, interactions_df.reindex(X_test_df.index)], axis=1
        )

        smote = SMOTE(random_state=42)
        X_train_resampled, y_train_resampled = smote.fit_resample(
            X_train_with_interactions.values, y_train
        )

        X_train_resampled_df = pd.DataFrame(
            X_train_resampled, columns=X_train_with_interactions.columns
        )
        X_test_with_interactions_df = pd.DataFrame(
            X_test_with_interactions.values, columns=X_test_with_interactions.columns
        )

        supervised_model_with_interactions = train_supervised_model(
            X_train_resampled_df.values, y_train_resampled
        )

        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train_resampled_df.values, y_train_resampled,
            test_size=0.2, stratify=y_train_resampled, random_state=42
        )
        supervised_model_with_interactions.fit(X_train_split, y_train_split)
        optimal_threshold = find_optimal_threshold(
            supervised_model_with_interactions, X_val, y_val
        )
        print(f"Optimal threshold (with interactions): {optimal_threshold:.4f}")

        probs = supervised_model_with_interactions.predict_proba(
            X_test_with_interactions_df.values
        )[:, 1]
        supervised_preds_with_interactions = (probs >= optimal_threshold).astype(int)

        anomaly_preds = anomaly_detector.predict(X_test_selected)
        anomaly_preds = np.where(anomaly_preds == -1, 1, 0)

        final_preds_with_interactions = np.where(
            supervised_preds_with_interactions == 1, 1, anomaly_preds
        )

        results_with_interactions = evaluate_model(
            y_test, final_preds_with_interactions, X_test_df,
            supervised_model_with_interactions, X_train_resampled_df.columns,
            log_file, sample_rate=0.1
        )
        print("\nResults with Feature Interactions and SMOTE:")
        print(results_with_interactions)

        importances_with_interactions = supervised_model_with_interactions.feature_importances_
        feature_importance_with_interactions = pd.DataFrame({
            'feature': X_train_resampled_df.columns,
            'importance': importances_with_interactions
        })
        feature_importance_with_interactions = feature_importance_with_interactions.sort_values(
            'importance', ascending=False
        )
        print("\nTop 10 Feature Importances (with Interactions):")
        print(feature_importance_with_interactions.head(10))

    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")

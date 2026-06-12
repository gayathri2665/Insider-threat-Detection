import os
import time
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc, precision_recall_curve
from src.database import DatabaseManager
from src.uba import UBAManager, FEATURE_NAMES
from src.model import EvidentialDetector, ComparativeModelsSuite

class PerformanceEvaluator:
    def __init__(self, db_manager, uba_manager):
        self.db = db_manager
        self.uba = uba_manager
        self.plots_dir = "data/plots"
        os.makedirs(self.plots_dir, exist_ok=True)

    def generate_evaluation_dataset(self):
        """Generates a test dataset containing normal activities and threat scenarios.
        Returns features X, labels y, and user list.
        """
        print("[*] Generating synthetic evaluation dataset (Normal vs. Threats)...")
        from src.simulator import DatabaseSimulator
        simulator = DatabaseSimulator(self.db)
        
        # Ensure we have profiles built
        self.uba.build_profiles_from_db()

        X = []
        y = []
        usernames = []
        
        # 1. Generate Normal sessions
        users = ["alice_hr", "bob_dev", "charlie_analyst", "service_acc"]
        for user in users:
            # Generate 20 test normal sessions per user
            for s in range(20):
                session_id = f"test_norm_{user}_{s:04d}"
                q_count = np.random.randint(5, 25) if user != "service_acc" else 2
                
                # Override shipper to avoid polluting audit log
                original_write = simulator.write_to_audit_log
                simulator.write_to_audit_log = lambda log: None
                
                queries = simulator.generate_normal_queries(user, session_id, q_count)
                
                # Restore shipper
                simulator.write_to_audit_log = original_write
                
                raw_feats = self.uba.extract_session_features(queries)
                norm_feats = self.uba.standardize_features(raw_feats, user)
                X.append(norm_feats)
                y.append(0.0) # Normal
                usernames.append(user)

        # 2. Generate Threats (5 sessions per scenario)
        threat_scenarios = [
            ("alice_hr", "mass_data_exfiltration"),
            ("bob_dev", "privilege_escalation"),
            ("charlie_analyst", "sql_injection"),
            ("charlie_analyst", "off_hours_burst"),
            ("service_acc", "hijacked_service_account"),
            ("stranger_danger", "repeated_failed_logins")
        ]

        for user, scenario in threat_scenarios:
            for _ in range(5):
                # Override shipper to avoid polluting audit log
                original_write = simulator.write_to_audit_log
                simulator.write_to_audit_log = lambda log: None
                
                queries = simulator.trigger_threat_scenario(scenario)
                
                # Restore shipper
                simulator.write_to_audit_log = original_write

                raw_feats = self.uba.extract_session_features(queries)
                norm_feats = self.uba.standardize_features(raw_feats, user)
                X.append(norm_feats)
                y.append(1.0) # Threat
                usernames.append(user)

        return np.array(X), np.array(y), usernames

    def run_evaluation(self, evidential_detector, baseline_suite):
        """Runs the entire evaluation suite, saves graphs, and prints comparison reports."""
        X_test, y_test, _ = self.generate_evaluation_dataset()
        print(f"[+] Generated {len(X_test)} evaluation samples (Normal: {np.sum(y_test==0)}, Threat: {np.sum(y_test==1)}).")

        results = {}

        # 1. Evaluate Deep Evidential Model
        print("[*] Evaluating Deep Evidential Model...")
        edl_preds = []
        edl_scores = []
        edl_latencies = []
        
        for x in X_test:
            start_time = time.perf_counter()
            pred = evidential_detector.predict(x)
            end_time = time.perf_counter()
            
            edl_latencies.append((end_time - start_time) * 1000) # milliseconds
            
            # Map decision to binary prediction: Normal Activity -> 0, others -> 1 (Threat/Uncertain)
            pred_bin = 0 if pred["decision"] == "Normal Activity" else 1
            edl_preds.append(pred_bin)
            edl_scores.append(pred["threat_score"])

        results["Deep Evidential Model"] = {
            "preds": np.array(edl_preds),
            "scores": np.array(edl_scores),
            "latencies": edl_latencies
        }

        # 2. Evaluate Comparative Baseline Models
        baseline_models = ["iforest", "ocsvm", "autoencoder", "rforest"]
        model_names_map = {
            "iforest": "Isolation Forest",
            "ocsvm": "One-Class SVM",
            "autoencoder": "Autoencoder Anomaly",
            "rforest": "Random Forest"
        }

        for model in baseline_models:
            print(f"[*] Evaluating {model_names_map[model]}...")
            preds = []
            scores = []
            latencies = []
            
            for x in X_test:
                start_time = time.perf_counter()
                if model == "autoencoder":
                    pred_bin = baseline_suite.autoencoder.predict(x)
                    score = baseline_suite.autoencoder.predict_score(x)
                else:
                    predictions_all = baseline_suite.predict_all(x)
                    pred_bin = predictions_all[model]
                    # Compute a soft score for ROC/PR calculations
                    if model == "iforest":
                        # Isolation Forest decision_function outputs lower values for anomalies
                        # Map to [0,1] range where higher means anomalous
                        score = -baseline_suite.iforest.decision_function(x.reshape(1, -1))[0]
                    elif model == "ocsvm":
                        score = -baseline_suite.ocsvm.decision_function(x.reshape(1, -1))[0]
                    elif model == "rforest":
                        score = baseline_suite.rforest.predict_proba(x.reshape(1, -1))[0, 1]
                        
                end_time = time.perf_counter()
                latencies.append((end_time - start_time) * 1000)
                
                preds.append(pred_bin)
                scores.append(score)

            results[model_names_map[model]] = {
                "preds": np.array(preds),
                "scores": np.array(scores),
                "latencies": latencies
            }

        # Calculate metrics for each model
        evaluation_report = {}
        for name, data in results.items():
            preds = data["preds"]
            scores = data["scores"]
            latencies = data["latencies"]
            
            tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
            
            accuracy = accuracy_score(y_test, preds)
            precision = precision_score(y_test, preds, zero_division=0)
            recall = recall_score(y_test, preds, zero_division=0)
            f1 = f1_score(y_test, preds, zero_division=0)
            
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
            avg_latency = np.mean(latencies)

            evaluation_report[name] = {
                "Accuracy": accuracy,
                "Precision": precision,
                "Recall": recall,
                "F1-Score": f1,
                "FPR": fpr,
                "FNR": fnr,
                "Latency (ms)": avg_latency,
                "TN": tn, "FP": fp, "FN": fn, "TP": tp,
                "scores": scores
            }

        # Print comparison report
        self.print_comparison_report(evaluation_report)
        
        # Generate and save evaluation plots
        self.plot_performance_curves(y_test, evaluation_report)
        self.plot_confusion_matrices(y_test, results)

        return evaluation_report

    def print_comparison_report(self, report):
        """Prints a structured ASCII report of model comparison."""
        print("\n" + "="*80)
        print("                 MODEL PERFORMANCE COMPARISON REPORT")
        print("="*80)
        print(f"{'Model Name':<25} | {'Acc':<6} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FPR':<6} | {'FNR':<6} | {'Latency':<8}")
        print("-"*80)
        for name, metrics in report.items():
            print(f"{name:<25} | "
                  f"{metrics['Accuracy']:.3f} | "
                  f"{metrics['Precision']:.3f} | "
                  f"{metrics['Recall']:.3f} | "
                  f"{metrics['F1-Score']:.3f} | "
                  f"{metrics['FPR']:.3f} | "
                  f"{metrics['FNR']:.3f} | "
                  f"{metrics['Latency (ms)']:.3f} ms")
        print("="*80)
        print(f"[*] Visualizations saved under: {self.plots_dir}/")

    def plot_performance_curves(self, y_true, report):
        """Plots ROC and Precision-Recall curves for all evaluated models."""
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        for name, metrics in report.items():
            scores = metrics["scores"]
            
            # Normalize scores to [0,1] for cleaner plotting if necessary
            min_s, max_s = np.min(scores), np.max(scores)
            if max_s - min_s > 0:
                norm_scores = (scores - min_s) / (max_s - min_s)
            else:
                norm_scores = scores
                
            # Compute ROC
            fpr, tpr, _ = roc_curve(y_true, norm_scores)
            roc_auc = auc(fpr, tpr)
            ax1.plot(fpr, tpr, label=f"{name} (AUC = {roc_auc:.3f})", lw=2)

            # Compute Precision-Recall
            precision, recall, _ = precision_recall_curve(y_true, norm_scores)
            pr_auc = auc(recall, precision)
            ax2.plot(recall, precision, label=f"{name} (AUC = {pr_auc:.3f})", lw=2)

        # ROC Subplot Formatting
        ax1.plot([0, 1], [0, 1], 'k--', lw=1.5)
        ax1.set_xlim([0.0, 1.0])
        ax1.set_ylim([0.0, 1.05])
        ax1.set_xlabel('False Positive Rate (FPR)', fontsize=11)
        ax1.set_ylabel('True Positive Rate (TPR)', fontsize=11)
        ax1.set_title('Receiver Operating Characteristic (ROC) Curves', fontsize=13, fontweight='bold')
        ax1.legend(loc="lower right")

        # PR Subplot Formatting
        ax2.set_xlim([0.0, 1.0])
        ax2.set_ylim([0.0, 1.05])
        ax2.set_xlabel('Recall (Sensitivity)', fontsize=11)
        ax2.set_ylabel('Precision', fontsize=11)
        ax2.set_title('Precision-Recall (PR) Curves', fontsize=13, fontweight='bold')
        ax2.legend(loc="lower left")

        plt.tight_layout()
        plt.savefig(f"{self.plots_dir}/model_performance_curves.png", dpi=300)
        plt.close()

    def plot_confusion_matrices(self, y_true, results):
        """Generates confusion matrix heatmaps side-by-side for comparison."""
        num_models = len(results)
        fig, axes = plt.subplots(1, num_models, figsize=(4 * num_models, 4))
        
        if num_models == 1:
            axes = [axes]

        for idx, (name, data) in enumerate(results.items()):
            preds = data["preds"]
            cm = confusion_matrix(y_true, preds, labels=[0, 1])
            
            sns.heatmap(
                cm, annot=True, fmt="d", cmap="Blues", cbar=False,
                xticklabels=["Normal", "Threat"], yticklabels=["Normal", "Threat"],
                ax=axes[idx], annot_kws={"size": 14, "weight": "bold"}
            )
            axes[idx].set_title(name, fontsize=12, fontweight='bold')
            axes[idx].set_xlabel('Predicted Label', fontsize=10)
            if idx == 0:
                axes[idx].set_ylabel('True Label', fontsize=10)
                
        plt.tight_layout()
        plt.savefig(f"{self.plots_dir}/confusion_matrices.png", dpi=300)
        plt.close()

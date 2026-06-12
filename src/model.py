import os
import json
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM

# Set random seeds for reproducibility
np.random.seed(42)

# Try importing torch to see if we are in a serverless environment like Vercel
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    torch.manual_seed(42)
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    # Define placeholder classes to avoid syntax/NameError when PyTorch is not installed
    class nn:
        class Module:
            pass

# Helper functions for pure NumPy forward inference (stable and overflow-resistant)
def numpy_relu(x):
    return np.maximum(0, x)

def numpy_softplus(x):
    # Stable softplus to prevent exp overflow for large inputs: log(1 + exp(-|x|)) + max(x, 0)
    return np.log1p(np.exp(-np.abs(x))) + np.maximum(x, 0)


# NumPy-only Inference Fallback for Evidential Network (Serverless Vercel Deployments)
class NumPyEvidentialDetector:
    def __init__(self, model_dir):
        self.model_dir = model_dir
        self.weights = {}
        self.loaded = self.load()

    def load(self):
        path = os.path.join(self.model_dir, "evidential_weights.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    self.weights = json.load(f)
                return True
            except Exception as e:
                print(f"[!] Error loading JSON weights: {e}")
        return False

    def predict(self, x_vector):
        if not self.loaded:
            return {
                "threat_score": 0.5,
                "confidence_score": 0.0,
                "uncertainty_score": 1.0,
                "decision": "Uncertain Activity",
                "evidence_normal": 0.0,
                "evidence_threat": 0.0
            }
        
        # Extract weight matrices and bias vectors
        W1 = np.array(self.weights["fc1.weight"])
        b1 = np.array(self.weights["fc1.bias"])
        W2 = np.array(self.weights["fc2.weight"])
        b2 = np.array(self.weights["fc2.bias"])
        W3 = np.array(self.weights["fc3.weight"])
        b3 = np.array(self.weights["fc3.bias"])
        
        # Forward Pass: y = x @ W.T + b
        x = np.array(x_vector)
        y1 = x @ W1.T + b1
        h1 = numpy_relu(y1)
        
        y2 = h1 @ W2.T + b2
        h2 = numpy_relu(y2)
        
        logits = h2 @ W3.T + b3
        evidence = numpy_softplus(logits)
        
        alpha = evidence + 1.0
        alpha_0 = alpha[0]
        alpha_1 = alpha[1]
        S = alpha_0 + alpha_1
        
        # Threat score & subjective logic metrics
        threat_score = alpha_1 / S
        uncertainty = 2.0 / S
        confidence = 1.0 - uncertainty
        
        if uncertainty >= 0.4:
            decision = "Uncertain Activity"
        elif threat_score >= 0.5:
            decision = "High-Confidence Threat"
        else:
            decision = "Normal Activity"
            
        return {
            "threat_score": float(threat_score),
            "confidence_score": float(confidence),
            "uncertainty_score": float(uncertainty),
            "decision": decision,
            "evidence_normal": float(alpha_0 - 1.0),
            "evidence_threat": float(alpha_1 - 1.0)
        }


# NumPy-only Inference Fallback for Autoencoder Network (Serverless Vercel Deployments)
class NumPyAutoencoderDetector:
    def __init__(self, model_dir):
        self.model_dir = model_dir
        self.weights = {}
        self.threshold = 1.5
        self.loaded = self.load()

    def load(self):
        path = os.path.join(self.model_dir, "autoencoder_weights.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    self.weights = data["weights"]
                    self.threshold = data["threshold"]
                return True
            except Exception as e:
                print(f"[!] Error loading Autoencoder JSON weights: {e}")
        return False

    def predict_score(self, x_vector):
        if not self.loaded:
            return 999.0
            
        W_e1 = np.array(self.weights["encoder.0.weight"])
        b_e1 = np.array(self.weights["encoder.0.bias"])
        W_e2 = np.array(self.weights["encoder.2.weight"])
        b_e2 = np.array(self.weights["encoder.2.bias"])
        
        W_d1 = np.array(self.weights["decoder.0.weight"])
        b_d1 = np.array(self.weights["decoder.0.bias"])
        W_d2 = np.array(self.weights["decoder.2.weight"])
        b_d2 = np.array(self.weights["decoder.2.bias"])
        
        # Reconstruct: Encoder -> Decoder
        x = np.array(x_vector)
        h1 = numpy_relu(x @ W_e1.T + b_e1)
        latent = numpy_relu(h1 @ W_e2.T + b_e2)
        h2 = numpy_relu(latent @ W_d1.T + b_d1)
        reconstructed = h2 @ W_d2.T + b_d2
        
        # MSE Reconstruction Error
        error = np.mean((x - reconstructed)**2)
        return float(error)

    def predict(self, x_vector):
        score = self.predict_score(x_vector)
        return 1 if score > self.threshold else 0


# -------------------------------------------------------------
# PYTORCH IMPLEMENTATIONS (Used locally for training & testing)
# -------------------------------------------------------------

if TORCH_AVAILABLE:
    class EvidentialNetwork(nn.Module):
        def __init__(self, input_dim=8, hidden_dim=16, num_classes=2):
            super(EvidentialNetwork, self).__init__()
            self.fc1 = nn.Linear(input_dim, hidden_dim)
            self.relu = nn.ReLU()
            self.dropout = nn.Dropout(0.1)
            self.fc2 = nn.Linear(hidden_dim, hidden_dim // 2)
            self.fc3 = nn.Linear(hidden_dim // 2, num_classes)
            
        def forward(self, x):
            out = self.fc1(x)
            out = self.relu(out)
            out = self.dropout(out)
            out = self.fc2(out)
            out = self.relu(out)
            logits = self.fc3(out)
            evidence = torch.nn.functional.softplus(logits)
            return evidence

    class AutoencoderNetwork(nn.Module):
        def __init__(self, input_dim=8, latent_dim=3):
            super(AutoencoderNetwork, self).__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 6),
                nn.ReLU(),
                nn.Linear(6, latent_dim),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 6),
                nn.ReLU(),
                nn.Linear(6, input_dim)
            )
            
        def forward(self, x):
            latent = self.encoder(x)
            reconstructed = self.decoder(latent)
            return reconstructed
else:
    # Placeholders to prevent import errors in other modules
    class EvidentialNetwork:
        pass
    class AutoencoderNetwork:
        pass


class EvidentialDetector:
    def __init__(self, input_dim=8, lr=0.005, epochs=80, batch_size=32):
        self.input_dim = input_dim
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.numpy_detector = None
        
        # Absolute path relative to this file to support running on Vercel
        self.model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "models"))
        
        if TORCH_AVAILABLE:
            self.model = EvidentialNetwork(input_dim=input_dim, num_classes=2)
            self.optimizer = optim.Adam(self.model.parameters(), lr=self.lr, weight_decay=1e-5)
            try:
                os.makedirs(self.model_dir, exist_ok=True)
            except Exception:
                pass
        else:
            self.numpy_detector = NumPyEvidentialDetector(self.model_dir)

    @staticmethod
    def loss_fn(alpha, y, epoch, max_epochs):
        """Bayes risk loss under Dirichlet distribution + KL divergence regularization."""
        if not TORCH_AVAILABLE:
            return 0.0
        S = torch.sum(alpha, dim=1, keepdim=True)
        loss_err = torch.sum(y * (torch.digamma(S) - torch.digamma(alpha)), dim=1)
        
        K = alpha.shape[1]
        beta = y + (1.0 - y) * alpha
        S_beta = torch.sum(beta, dim=1, keepdim=True)
        
        lnB = torch.lgamma(beta).sum(dim=1, keepdim=True) - torch.lgamma(S_beta)
        lnB_uni = torch.lgamma(torch.ones_like(beta)).sum(dim=1, keepdim=True) - torch.lgamma(torch.tensor(float(K)))
        
        dg_S = torch.digamma(S_beta)
        dg_beta = torch.digamma(beta)
        
        kl = torch.sum((beta - 1.0) * (dg_beta - dg_S), dim=1, keepdim=True) + lnB_uni - lnB
        kl_coeff = min(1.0, epoch / max_epochs) * 0.2
        
        total_loss = loss_err + kl_coeff * kl.squeeze()
        return total_loss.mean()

    def train(self, X, y):
        """Trains the Deep Evidential Model."""
        if not TORCH_AVAILABLE:
            print("[!] PyTorch is not installed in this environment. Training is disabled.")
            return
            
        self.model.train()
        X_tensor = torch.tensor(X, dtype=torch.float32)
        
        y_one_hot = np.zeros((len(y), 2))
        for idx, val in enumerate(y):
            y_one_hot[idx, int(val)] = 1.0
        y_tensor = torch.tensor(y_one_hot, dtype=torch.float32)
        
        dataset = torch.utils.data.TensorDataset(X_tensor, y_tensor)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        for epoch in range(1, self.epochs + 1):
            epoch_loss = 0.0
            for batch_x, batch_y in loader:
                self.optimizer.zero_grad()
                evidence = self.model(batch_x)
                alpha = evidence + 1.0
                loss = self.loss_fn(alpha, batch_y, epoch, self.epochs)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
                
        # Save PyTorch checkpoints (ignore read-only file systems like Vercel)
        try:
            torch.save(self.model.state_dict(), f"{self.model_dir}/evidential_model.pth")
        except Exception as e:
            print(f"[!] Warning: Could not save model weights (read-only filesystem): {e}")
            
        # Export weight parameters to JSON for NumPy inference fallback
        try:
            weights = {}
            for name, param in self.model.state_dict().items():
                weights[name] = param.cpu().numpy().tolist()
            with open(os.path.join(self.model_dir, "evidential_weights.json"), "w") as f:
                json.dump(weights, f)
            print("[+] Exported evidential network weights to JSON.")
        except Exception as e:
            print(f"[!] Warning: Could not export JSON weights: {e}")
            
        # Update NumPy detector instance
        self.numpy_detector = NumPyEvidentialDetector(self.model_dir)

    def load(self):
        """Loads model weights."""
        if not TORCH_AVAILABLE:
            self.numpy_detector = NumPyEvidentialDetector(self.model_dir)
            return self.numpy_detector.loaded
            
        model_path = f"{self.model_dir}/evidential_model.pth"
        if os.path.exists(model_path):
            try:
                self.model.load_state_dict(torch.load(model_path))
                self.model.eval()
                return True
            except Exception:
                # Fallback to NumPy load if PyTorch load fails (e.g. version mismatch)
                self.numpy_detector = NumPyEvidentialDetector(self.model_dir)
                return self.numpy_detector.loaded
        return False

    def predict(self, x_vector):
        """Predicts the threat score, confidence, uncertainty and decision."""
        if not TORCH_AVAILABLE or self.numpy_detector:
            if not self.numpy_detector:
                self.numpy_detector = NumPyEvidentialDetector(self.model_dir)
            return self.numpy_detector.predict(x_vector)
            
        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.tensor(x_vector, dtype=torch.float32).unsqueeze(0)
            evidence = self.model(x_tensor)
            alpha = evidence + 1.0
            
            alpha_0 = alpha[0, 0].item()
            alpha_1 = alpha[0, 1].item()
            S = alpha_0 + alpha_1
            
            threat_score = alpha_1 / S
            uncertainty = 2.0 / S
            confidence = 1.0 - uncertainty
            
            if uncertainty >= 0.4:
                decision = "Uncertain Activity"
            elif threat_score >= 0.5:
                decision = "High-Confidence Threat"
            else:
                decision = "Normal Activity"
                
            return {
                "threat_score": threat_score,
                "confidence_score": confidence,
                "uncertainty_score": uncertainty,
                "decision": decision,
                "evidence_normal": alpha_0 - 1.0,
                "evidence_threat": alpha_1 - 1.0
            }


class AutoencoderDetector:
    def __init__(self, input_dim=8, lr=0.01, epochs=80, batch_size=32):
        self.input_dim = input_dim
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.numpy_detector = None
        
        self.model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "models"))
        
        if TORCH_AVAILABLE:
            self.model = AutoencoderNetwork(input_dim=input_dim)
            self.optimizer = optim.Adam(self.model.parameters(), lr=self.lr)
            self.criterion = nn.MSELoss()
            self.threshold = 1.5
        else:
            self.numpy_detector = NumPyAutoencoderDetector(self.model_dir)
        
    def train(self, X_normal):
        """Trains Autoencoder on normal data."""
        if not TORCH_AVAILABLE:
            print("[!] PyTorch is not installed. Training disabled.")
            return
            
        self.model.train()
        X_tensor = torch.tensor(X_normal, dtype=torch.float32)
        dataset = torch.utils.data.TensorDataset(X_tensor)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        for epoch in range(1, self.epochs + 1):
            epoch_loss = 0.0
            for batch_x, in loader:
                self.optimizer.zero_grad()
                reconstructed = self.model(batch_x)
                loss = self.criterion(reconstructed, batch_x)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
                
        self.model.eval()
        with torch.no_grad():
            reconstructed_all = self.model(X_tensor)
            errors = torch.mean((reconstructed_all - X_tensor)**2, dim=1).numpy()
            self.threshold = float(np.percentile(errors, 95))
            
        # Save PyTorch checkpoints
        try:
            torch.save({
                "state_dict": self.model.state_dict(),
                "threshold": self.threshold
            }, f"{self.model_dir}/autoencoder_model.pth")
        except Exception as e:
            print(f"[!] Warning: Could not save Autoencoder weights (read-only filesystem): {e}")
            
        # Export weight parameters to JSON for NumPy inference fallback
        try:
            weights = {}
            for name, param in self.model.state_dict().items():
                weights[name] = param.cpu().numpy().tolist()
            with open(os.path.join(self.model_dir, "autoencoder_weights.json"), "w") as f:
                json.dump({
                    "weights": weights,
                    "threshold": float(self.threshold)
                }, f)
            print("[+] Exported autoencoder network weights to JSON.")
        except Exception as e:
            print(f"[!] Warning: Could not export Autoencoder JSON weights: {e}")
            
        # Update NumPy detector instance
        self.numpy_detector = NumPyAutoencoderDetector(self.model_dir)
        
    def load(self):
        if not TORCH_AVAILABLE:
            self.numpy_detector = NumPyAutoencoderDetector(self.model_dir)
            return self.numpy_detector.loaded
            
        path = f"{self.model_dir}/autoencoder_model.pth"
        if os.path.exists(path):
            try:
                checkpoint = torch.load(path)
                self.model.load_state_dict(checkpoint["state_dict"])
                self.threshold = checkpoint["threshold"]
                self.model.eval()
                return True
            except Exception:
                # Fallback to NumPy load if PyTorch load fails
                self.numpy_detector = NumPyAutoencoderDetector(self.model_dir)
                return self.numpy_detector.loaded
        return False

    def predict_score(self, x_vector):
        if not TORCH_AVAILABLE or self.numpy_detector:
            if not self.numpy_detector:
                self.numpy_detector = NumPyAutoencoderDetector(self.model_dir)
            return self.numpy_detector.predict_score(x_vector)
            
        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.tensor(x_vector, dtype=torch.float32).unsqueeze(0)
            reconstructed = self.model(x_tensor)
            error = torch.mean((reconstructed - x_tensor)**2).item()
            return error

    def predict(self, x_vector):
        if not TORCH_AVAILABLE or self.numpy_detector:
            if not self.numpy_detector:
                self.numpy_detector = NumPyAutoencoderDetector(self.model_dir)
            return self.numpy_detector.predict(x_vector)
            
        score = self.predict_score(x_vector)
        return 1 if score > self.threshold else 0


class ComparativeModelsSuite:
    def __init__(self, input_dim=8):
        self.input_dim = input_dim
        self.iforest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.ocsvm = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
        self.rforest = RandomForestClassifier(n_estimators=100, random_state=42)
        self.autoencoder = AutoencoderDetector(input_dim=input_dim)
        
    def train_all(self, X_train, y_train):
        self.iforest.fit(X_train)
        self.rforest.fit(X_train, y_train)
        X_normal = X_train[y_train == 0]
        self.ocsvm.fit(X_normal)
        self.autoencoder.train(X_normal)
        
    def predict_all(self, x_vector):
        x_reshaped = x_vector.reshape(1, -1)
        iforest_pred = 1 if self.iforest.predict(x_reshaped)[0] == -1 else 0
        ocsvm_pred = 1 if self.ocsvm.predict(x_reshaped)[0] == -1 else 0
        rforest_pred = int(self.rforest.predict(x_reshaped)[0])
        ae_pred = self.autoencoder.predict(x_vector)
        
        return {
            "iforest": iforest_pred,
            "ocsvm": ocsvm_pred,
            "rforest": rforest_pred,
            "autoencoder": ae_pred
        }

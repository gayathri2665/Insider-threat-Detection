import os
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM

# Set random seeds for reproducibility
torch.manual_seed(42)
np.random.seed(42)

# Custom Deep Evidential Classification Model in PyTorch
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
        # For Evidential Deep Learning, the output represents non-negative evidence.
        # We apply Softplus (or ReLU) to guarantee non-negativity.
        evidence = torch.nn.functional.softplus(logits)
        return evidence

class EvidentialDetector:
    def __init__(self, input_dim=8, lr=0.005, epochs=80, batch_size=32):
        self.input_dim = input_dim
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.model = EvidentialNetwork(input_dim=input_dim, num_classes=2)
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.lr, weight_decay=1e-5)
        self.model_dir = "data/models"
        os.makedirs(self.model_dir, exist_ok=True)

    @staticmethod
    def loss_fn(alpha, y, epoch, max_epochs):
        """Bayes risk loss under Dirichlet distribution + KL divergence regularization."""
        S = torch.sum(alpha, dim=1, keepdim=True)
        # Bayes risk loss (first term) using digamma function
        loss_err = torch.sum(y * (torch.digamma(S) - torch.digamma(alpha)), dim=1)
        
        # KL divergence regularization (second term) to penalize misleading evidence
        K = alpha.shape[1]
        beta = y + (1.0 - y) * alpha
        S_beta = torch.sum(beta, dim=1, keepdim=True)
        
        lnB = torch.lgamma(beta).sum(dim=1, keepdim=True) - torch.lgamma(S_beta)
        lnB_uni = torch.lgamma(torch.ones_like(beta)).sum(dim=1, keepdim=True) - torch.lgamma(torch.tensor(float(K)))
        
        dg_S = torch.digamma(S_beta)
        dg_beta = torch.digamma(beta)
        
        kl = torch.sum((beta - 1.0) * (dg_beta - dg_S), dim=1, keepdim=True) + lnB_uni - lnB
        
        # Annealing coefficient for KL term
        kl_coeff = min(1.0, epoch / max_epochs) * 0.2
        
        total_loss = loss_err + kl_coeff * kl.squeeze()
        return total_loss.mean()

    def train(self, X, y):
        """Trains the Deep Evidential Model on features X (np.array) and labels y (np.array).
        y should be binary labels: 0 for Normal, 1 for Threat.
        """
        self.model.train()
        X_tensor = torch.tensor(X, dtype=torch.float32)
        
        # Convert binary labels to one-hot: [Normal, Threat]
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
                alpha = evidence + 1.0  # Dirichlet parameters
                loss = self.loss_fn(alpha, batch_y, epoch, self.epochs)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
            
            if epoch % 20 == 0 or epoch == 1:
                avg_loss = epoch_loss / len(X)
                # print(f"Epoch {epoch}/{self.epochs} - Loss: {avg_loss:.4f}")
                
        # Save model weights after training
        torch.save(self.model.state_dict(), f"{self.model_dir}/evidential_model.pth")
        
    def load(self):
        """Loads model weights."""
        model_path = f"{self.model_dir}/evidential_model.pth"
        if os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path))
            self.model.eval()
            return True
        return False

    def predict(self, x_vector):
        """Predicts the threat score, confidence, uncertainty and decision for a single feature vector.
        x_vector: numpy array of size 8.
        """
        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.tensor(x_vector, dtype=torch.float32).unsqueeze(0)
            evidence = self.model(x_tensor)
            alpha = evidence + 1.0
            
            alpha_0 = alpha[0, 0].item() # Normal evidence + 1
            alpha_1 = alpha[0, 1].item() # Threat evidence + 1
            S = alpha_0 + alpha_1
            
            # Mathematical quantities:
            threat_score = alpha_1 / S          # Expected threat probability
            uncertainty = 2.0 / S               # Epistemic Uncertainty (K / S)
            confidence = 1.0 - uncertainty      # Confidence (1 - u)
            
            # Decision threshold logic:
            # High uncertainty (u >= 0.4) -> Uncertain (manual review needed)
            # Low uncertainty and threat >= 0.5 -> Threat
            # Low uncertainty and threat < 0.5 -> Normal
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


# Baseline 1: Standard Autoencoder Anomaly Detector
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

class AutoencoderDetector:
    def __init__(self, input_dim=8, lr=0.01, epochs=80, batch_size=32):
        self.input_dim = input_dim
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.model = AutoencoderNetwork(input_dim=input_dim)
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.lr)
        self.criterion = nn.MSELoss()
        self.threshold = 1.5 # Will be set dynamically based on reconstruction errors on normal data
        self.model_dir = "data/models"
        
    def train(self, X_normal):
        """Trains on Normal data only (unsupervised anomaly detection)."""
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
                
        # Set threshold to 95th percentile of reconstruction errors on training set
        self.model.eval()
        with torch.no_grad():
            reconstructed_all = self.model(X_tensor)
            errors = torch.mean((reconstructed_all - X_tensor)**2, dim=1).numpy()
            self.threshold = float(np.percentile(errors, 95))
            
        torch.save({
            "state_dict": self.model.state_dict(),
            "threshold": self.threshold
        }, f"{self.model_dir}/autoencoder_model.pth")
        
    def load(self):
        path = f"{self.model_dir}/autoencoder_model.pth"
        if os.path.exists(path):
            checkpoint = torch.load(path)
            self.model.load_state_dict(checkpoint["state_dict"])
            self.threshold = checkpoint["threshold"]
            self.model.eval()
            return True
        return False

    def predict_score(self, x_vector):
        """Returns the reconstruction error as anomaly score."""
        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.tensor(x_vector, dtype=torch.float32).unsqueeze(0)
            reconstructed = self.model(x_tensor)
            error = torch.mean((reconstructed - x_tensor)**2).item()
            return error

    def predict(self, x_vector):
        score = self.predict_score(x_vector)
        return 1 if score > self.threshold else 0


# Baseline Suite Wrapper
class ComparativeModelsSuite:
    def __init__(self, input_dim=8):
        self.input_dim = input_dim
        # Baselines
        self.iforest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.ocsvm = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
        self.rforest = RandomForestClassifier(n_estimators=100, random_state=42)
        self.autoencoder = AutoencoderDetector(input_dim=input_dim)
        
    def train_all(self, X_train, y_train):
        """Trains all comparative baselines.
        X_train: training features (mixed normal/anomalous for RF, normal-only for OC-SVM/AE, mixed for I-Forest)
        y_train: training labels
        """
        # Isolation Forest can train on mixed or normal. We train it on all training features.
        self.iforest.fit(X_train)
        
        # Random Forest is supervised, trains on mixed.
        self.rforest.fit(X_train, y_train)
        
        # One-Class SVM and Autoencoder train on Normal data only
        X_normal = X_train[y_train == 0]
        self.ocsvm.fit(X_normal)
        self.autoencoder.train(X_normal)
        
    def predict_all(self, x_vector):
        """Predicts anomaly status (0=Normal, 1=Anomaly) for all models."""
        x_reshaped = x_vector.reshape(1, -1)
        
        # Isolation Forest returns -1 for anomaly, 1 for normal
        iforest_pred = 1 if self.iforest.predict(x_reshaped)[0] == -1 else 0
        
        # One-Class SVM returns -1 for anomaly, 1 for normal
        ocsvm_pred = 1 if self.ocsvm.predict(x_reshaped)[0] == -1 else 0
        
        # Random Forest returns class label directly
        rforest_pred = int(self.rforest.predict(x_reshaped)[0])
        
        # Autoencoder
        ae_pred = self.autoencoder.predict(x_vector)
        
        return {
            "iforest": iforest_pred,
            "ocsvm": ocsvm_pred,
            "rforest": rforest_pred,
            "autoencoder": ae_pred
        }

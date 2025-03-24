import json
import os

import torch
import torch.nn as nn
import torch.optim as optim
from models.ncf import NCF
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score
from torch.utils.data import DataLoader
from tqdm import tqdm
from utils.data_processing import (InteractionDataset, augment_data, load_data,
                                   process_data, split_data)

# Definește calea către directorul data și fișierul JSON
data_directory = os.path.join(os.getcwd(), 'recommandations', 'data')
file_path = os.path.join(data_directory, 'locations_large.json')

# Verifică dacă fișierul există
if not os.path.exists(file_path):
    raise FileNotFoundError(f"File {file_path} does not exist.")

# Încarcă datele din fișierul JSON
data = load_data(file_path)  # Asigură-te că folosești calea corectă

# Procesează datele
interactions, num_users, num_items = process_data(data)

# Augmentează datele
interactions = augment_data(interactions, num_augmentations=1)

# Împarte datele în seturi de antrenament și de test
train_data, test_data = split_data(interactions)

# Creează dataset-urile PyTorch
train_dataset = InteractionDataset(train_data)
test_dataset = InteractionDataset(test_data)

# Creează DataLoader-urile
train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

# Initializează modelul NCF
model = NCF(num_users, num_items)

# Definește criteriul și optimizerul
criterion = nn.BCELoss()
optimizer = optim.AdamW(model.parameters(), lr=0.0005, weight_decay=0.01)
scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=5)

def evaluate(model, dataloader):
    model.eval()
    targets, predictions = [], []
    with torch.no_grad():
        for user, item, rating in dataloader:
            user = user.to(torch.long)
            item = item.to(torch.long)
            rating = rating.float()
            rating_binary = (rating >= 3).float()  # Transformam ratingul in format binar
            output = model(user, item)
            targets.extend(rating_binary.tolist())
            predictions.extend(output.squeeze().tolist())
    
    auc = roc_auc_score(targets, predictions)
    
    # Binarize predictions based on a threshold of 0.5 for confusion matrix and accuracy
    binary_predictions = [1 if pred >= 0.5 else 0 for pred in predictions]
    
    acc = accuracy_score(targets, binary_predictions)
    cm = confusion_matrix(targets, binary_predictions)
    
    return auc, acc, cm

# Antrenarea modelului
num_epochs = 100
best_auc = 0
patience = 10
patience_counter = 0

for epoch in range(num_epochs):
    model.train()
    total_loss = 0
    with tqdm(total=len(train_loader), desc=f"Epoch {epoch+1}/{num_epochs}", unit="batch") as pbar:
        for user, item, rating in train_loader:
            user = user.to(torch.long)
            item = item.to(torch.long)
            rating = rating.float()
            rating_binary = (rating >= 3).float()  # Transformam ratingul in format binar
            optimizer.zero_grad()
            output = model(user, item)
            loss = criterion(output.squeeze(), rating_binary)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            pbar.set_postfix(loss=total_loss / (pbar.n + 1))
            pbar.update(1)
    
    auc, acc, cm = evaluate(model, test_loader)
    scheduler.step(auc)
    
    if auc > best_auc:
        best_auc = auc
        patience_counter = 0
        # Salvează modelul antrenat la fiecare îmbunătățire a AUC-ului
        torch.save(model.state_dict(), 'ncf_model.pth')
    else:
        patience_counter += 1
    
    print(f"Epoch {epoch+1}/{num_epochs}, Loss: {total_loss/len(train_loader):.4f}, AUC: {auc:.4f}, Accuracy: {acc:.4f}")
    print(f"Confusion Matrix:\n{cm}")
    
    if patience_counter >= patience:
        print("Early stopping due to no improvement in AUC.")
        break

# Evaluarea finală a modelului
final_auc, final_acc, final_cm = evaluate(model, test_loader)
print(f"Final AUC: {final_auc:.4f}, Final Accuracy: {final_acc:.4f}")
print(f"Final Confusion Matrix:\n{final_cm}")

# Salvează num_users și num_items în metadata.json
with open('metadata.json', 'w', encoding='utf-8') as f:
    json.dump({'num_users': int(num_users), 'num_items': int(num_items)}, f)  # Convert to int before serializing

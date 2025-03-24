import json
import os
import sys

import torch

from models.ncf import NCF

# Setează codarea consolei la utf-8
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

def generate_recommendations(model_path, user_id, locations, num_users, num_items, threshold=0.5):
    print("Începe generarea recomandărilor...")  # Diagnostic
    # Încarcă modelul antrenat
    model = NCF(num_users, num_items)
    model.load_state_dict(torch.load(model_path))
    model.eval()
    print("Model încărcat...")  # Diagnostic

    # Transformați locațiile din JSON în formatul necesar
    location_ids = [loc["Id"] for loc in locations]
    proximities = [loc.get("proximity", "no") for loc in locations]

    user_tensor = torch.LongTensor([user_id] * len(location_ids))
    item_tensor = torch.LongTensor(location_ids)

    print(f"user_tensor size: {user_tensor.size()}")
    print(f"item_tensor size: {item_tensor.size()}")

    with torch.no_grad():
        predictions = model(user_tensor, item_tensor).squeeze().tolist()

    if isinstance(predictions, float):
        predictions = [predictions]

    # Afișează ID-ul și scorul fiecărei locații
    print("Scoruri locații:")  # Diagnostic
    for loc_id, score in zip(location_ids, predictions):
        print(f"Locația {loc_id}: {score:.4f}")

    # Filtrează locațiile pe baza proximității și a pragului
    recommendations = [(loc_id, score) for loc_id, score, prox in zip(location_ids, predictions, proximities) if score >= threshold and prox == "yes"]

    # Sortează recomandările în funcție de scorul predicțiilor
    recommendations = sorted(recommendations, key=lambda x: x[1], reverse=True)

    if recommendations:
        # Dacă există recomandări peste prag
        if len(recommendations) > 5:
            result = [loc_id for loc_id, _ in recommendations[:5]]
        else:
            result = [loc_id for loc_id, _ in recommendations]
    else:
        # Dacă nu există recomandări peste prag, returnează primele 30% din toate locațiile din proximitate
        proximity_predictions = [(loc_id, score) for loc_id, score, prox in zip(location_ids, predictions, proximities) if prox == "yes"]
        top_30_percent = max(1, int(len(proximity_predictions) * 0.3))
        top_recommendations = sorted(proximity_predictions, key=lambda x: x[1], reverse=True)[:top_30_percent]
        result = [loc_id for loc_id, _ in top_recommendations]

    print(f"Recomandări generate: {result}")  # Diagnostic
    return result

# Exemplu de utilizare a funcției de recomandare
if __name__ == "__main__":
    input_file_path = os.path.join(os.path.dirname(__file__), '..', 'input_data.json')

    with open(input_file_path, 'r', encoding='utf-8') as f:
        input_data = json.load(f)
    
    user_id = input_data['user_id']
    locations = input_data['locations']
    threshold = input_data['threshold']
    model_path = os.path.join(os.path.dirname(__file__), "ncf_model.pth")
    metadata_path = os.path.join(os.path.dirname(__file__), "metadata.json")

    with open(metadata_path, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    num_users = metadata['num_users']
    num_items = metadata['num_items']

    recommendations = generate_recommendations(model_path, user_id, locations, num_users, num_items, threshold)

    output_file_path = os.path.join(os.path.dirname(__file__), '..', 'output_data.json')
    with open(output_file_path, 'w', encoding='utf-8') as f:
        json.dump(recommendations, f)

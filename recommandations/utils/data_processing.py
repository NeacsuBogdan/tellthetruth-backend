import json

import pandas as pd
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset


def load_data(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def process_data(data):
    interactions = []
    for location in data:
        loc_id = location['Id']
        reviews = location.get('Recenzii', [])
        for review in reviews:
            user_id = review['idU']
            score = review['scor']
            interactions.append((user_id, loc_id, score))
    interactions_df = pd.DataFrame(interactions, columns=['user', 'item', 'rating'])
    num_users = interactions_df['user'].max() + 1
    num_items = interactions_df['item'].max() + 1
    return interactions_df, num_users, num_items

def augment_data(interactions, num_augmentations=1):
    augmented_interactions = interactions.copy()
    for _ in range(num_augmentations):
        shuffled = interactions.sample(frac=1).reset_index(drop=True)
        augmented_interactions = pd.concat([augmented_interactions, shuffled])
    return augmented_interactions

def split_data(interactions):
    train_data, test_data = train_test_split(interactions, test_size=0.2, random_state=42)
    return train_data, test_data

class InteractionDataset(Dataset):
    def __init__(self, interactions):
        self.interactions = interactions

    def __len__(self):
        return len(self.interactions)

    def __getitem__(self, idx):
        user = self.interactions.iloc[idx, 0]
        item = self.interactions.iloc[idx, 1]
        rating = self.interactions.iloc[idx, 2]
        return user, item, rating

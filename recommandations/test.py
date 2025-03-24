import json

import torch

from models.ncf import NCF

# Load metadata
with open('metadata.json', 'r', encoding='utf-8') as f:
    metadata = json.load(f)
num_users = metadata['num_users']
num_items = metadata['num_items']

# Load and export the model
model = NCF(num_users, num_items)
model.load_state_dict(torch.load('ncf_model.pth'))
model.eval()

# Convert the model to TorchScript
example_input = (torch.LongTensor([0]), torch.LongTensor([0]))
traced_model = torch.jit.trace(model, example_input)
traced_model.save("ncf_model.pt")

import torch
import torch.nn as nn


class NCF(nn.Module):
    def __init__(self, num_users, num_items, embedding_dim=128, hidden_layers=[256, 128, 64, 32], dropout=0.2):
        super(NCF, self).__init__()
        self.num_users = num_users
        self.num_items = num_items

        # Adăugăm 1 pentru utilizatorii și locațiile necunoscute
        self.user_embedding = nn.Embedding(num_users + 1, embedding_dim)
        self.item_embedding = nn.Embedding(num_items + 1, embedding_dim)

        self.gmf = nn.Sequential(
            nn.Linear(embedding_dim, embedding_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        self.mlp = nn.Sequential()
        input_size = embedding_dim * 2  # Concatenation of user and item embeddings
        for i in range(len(hidden_layers)):
            self.mlp.add_module(f"layer{i}", nn.Linear(input_size, hidden_layers[i]))
            self.mlp.add_module(f"batchnorm{i}", nn.BatchNorm1d(hidden_layers[i]))
            self.mlp.add_module(f"relu{i}", nn.ReLU())
            self.mlp.add_module(f"dropout{i}", nn.Dropout(dropout))
            input_size = hidden_layers[i]

        self.output_layer = nn.Linear(hidden_layers[-1] + embedding_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, user, item):
        # Orice utilizator sau locație necunoscută va fi mapată la ultimul index
        user = torch.where(user >= self.num_users, self.num_users, user)
        item = torch.where(item >= self.num_items, self.num_items, item)

        user_embedding = self.user_embedding(user)
        item_embedding = self.item_embedding(item)

        gmf_output = self.gmf(user_embedding * item_embedding)
        mlp_input = torch.cat([user_embedding, item_embedding], dim=1)
        mlp_output = self.mlp(mlp_input)

        output = torch.cat([gmf_output, mlp_output], dim=1)
        output = self.output_layer(output)
        output = self.sigmoid(output)
        return output

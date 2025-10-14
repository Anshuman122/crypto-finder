import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.nn import GCNConv, global_mean_pool


class CryptoClassifierMLP(nn.Module):

    def __init__(self,
 
                 vocab_size: int = 1000,  
                 embedding_dim: int = 128,    
                 nhead: int = 4,             
                 num_transformer_layers: int = 2,
                 hidden_size: int = 128,
                 num_classes: int = 2):
        
        super(CryptoClassifierMLP, self).__init__()

        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        encoder_layer = nn.TransformerEncoderLayer(d_model=embedding_dim, nhead=nhead, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_transformer_layers)

        self.conv1 = GCNConv(embedding_dim, hidden_size)
        self.conv2 = GCNConv(hidden_size, hidden_size // 2)


        self.output_layer = nn.Linear(hidden_size // 2, num_classes)
        self.dropout = nn.Dropout(p=0.5)

    def forward(self, x, edge_index, batch):

        node_embeddings = self.embedding(x)
        transformer_out = self.transformer_encoder(node_embeddings)

        node_features = transformer_out[:, 0, :]

        graph_features = self.conv1(node_features, edge_index)
        graph_features = F.relu(graph_features)
        graph_features = self.dropout(graph_features)
        
        graph_features = self.conv2(graph_features, edge_index)
        graph_features = F.relu(graph_features)

        graph_embedding = global_mean_pool(graph_features, batch)

        x = self.dropout(graph_embedding)
        x = self.output_layer(x)
        
        return x

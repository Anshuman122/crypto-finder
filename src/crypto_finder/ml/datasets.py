
import torch
from torch.utils.data import Dataset
from pathlib import Path
import json
import pandas as pd
from typing import List, Tuple

from crypto_finder.common.logging import log
from crypto_finder.ml.features import extract_features_from_function

class CryptoFuncDataset(Dataset):
 

    def __init__(self, data_dir: Path, annotations_file: Path):

        self.data_dir = data_dir

        try:
            self.annotations = pd.read_csv(annotations_file)
        except FileNotFoundError:
            log.error(f"Annotations file not found: {annotations_file}")
            raise
        
        self.samples: List[Tuple[Dict, int]] = []
        self._load_data()

    def _load_data(self):

        log.info("Dataset load ho raha hai...")
        for idx, row in self.annotations.iterrows():
            json_filename = row['filename']
            label_str = row['label']

            label = 1 if label_str == "crypto" else 0
            
            json_path = self.data_dir / json_filename
            if not json_path.exists():
                log.warning(f"JSON file not found, skipping: {json_path}")
                continue
            
            with open(json_path, 'r') as f:
                data = json.load(f)
                for func in data.get("functions", []):
                    self.samples.append((func, label))
        
        log.success(f"Dataset loaded successfully. Total functions: {len(self.samples)}")

    def __len__(self) -> int:

        return len(self.samples)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:

        func_data, label = self.samples[idx]

        features = extract_features_from_function(func_data)

        feature_tensor = torch.from_numpy(features)
        label_tensor = torch.tensor(label, dtype=torch.long)
        
        return feature_tensor, label_tensor

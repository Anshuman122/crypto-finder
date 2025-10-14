
import typer
from pathlib import Path
import torch
from torch.utils.data import DataLoader
from sklearn.metrics import classification_report

from crypto_finder.ml.datasets import CryptoFuncDataset
from crypto_finder.ml.models import CryptoClassifierMLP
from crypto_finder.common.logging import log

app = typer.Typer()

@app.command()
def evaluate(
    model_path: Path = typer.Option(..., "--model-path", help="Trained model (.pth file) ka path.", exists=True),
    data_dir: Path = typer.Option(..., "--data-dir", help="Lifted JSON files wali test data directory."),
    annotations_file: Path = typer.Option(..., "--annotations-file", help="Test data ke labels wali CSV file."),
    batch_size: int = typer.Option(32, "--batch-size"),
):

    log.info("Model evaluation is starting....")

    test_dataset = CryptoFuncDataset(data_dir=data_dir, annotations_file=annotations_file)
    test_loader = DataLoader(test_dataset, batch_size=batch_size)

    model = CryptoClassifierMLP()
    try:
        model.load_state_dict(torch.load(model_path))
    except Exception as e:
        log.error(f"Model load karne me error: {e}")
        raise typer.Exit(code=1)

    model.eval()

    all_preds = []
    all_labels = []

    with torch.no_grad():
        for features, labels in test_loader:
            outputs = model(features)
          
            _, predicted = torch.max(outputs.data, 1)
            
            all_preds.extend(predicted.numpy())
            all_labels.extend(labels.numpy())

    log.success("Evaluation complete.")


    report = classification_report(
        all_labels, 
        all_preds, 
        target_names=["non-crypto", "crypto"]
    )
    
    typer.secho("\n--- Classification Report ---", fg=typer.colors.CYAN, bold=True)
    print(report)

if __name__ == "__main__":
    app()

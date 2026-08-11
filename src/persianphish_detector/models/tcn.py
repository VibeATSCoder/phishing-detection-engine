from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

import numpy as np

from ..url_utils import tcn_domain_input


MAX_URL_BYTES = 512
PAD_ID = 0
BYTE_OFFSET = 1
VOCAB_SIZE = 257
TCN_INPUT_CONTRACT = "normalized_hostname_only_v1"


def encode_url(url: str, max_length: int = MAX_URL_BYTES) -> np.ndarray:
    """Encode only the normalized hostname for the URL TCN.

    This deliberately leaves the RF's full URL/HTML feature extraction
    unchanged.  Training and ONNX inference share this function, so the TCN
    never consumes path or query bytes.
    """
    data = tcn_domain_input(url).encode("utf-8", errors="replace")[:max_length]
    encoded = np.zeros(max_length, dtype=np.int64)
    if data:
        encoded[: len(data)] = np.frombuffer(data, dtype=np.uint8).astype(np.int64) + BYTE_OFFSET
    return encoded


try:
    import torch
    from torch import nn

    class ResidualTCNBlock(nn.Module):
        def __init__(self, in_channels: int, out_channels: int, dilation: int, dropout: float = 0.1) -> None:
            super().__init__()
            padding = dilation
            self.network = nn.Sequential(
                nn.Conv1d(in_channels, out_channels, kernel_size=3, padding=padding, dilation=dilation),
                nn.BatchNorm1d(out_channels),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Conv1d(out_channels, out_channels, kernel_size=3, padding=padding, dilation=dilation),
                nn.BatchNorm1d(out_channels),
                nn.ReLU(),
                nn.Dropout(dropout),
            )
            self.skip = nn.Identity() if in_channels == out_channels else nn.Conv1d(in_channels, out_channels, 1)

        def forward(self, value: "torch.Tensor") -> "torch.Tensor":
            return torch.relu(self.network(value) + self.skip(value))


    class URLTCN(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embedding = nn.Embedding(VOCAB_SIZE, 32, padding_idx=PAD_ID)
            channels = [32, 64, 64, 128, 128]
            dilations = [1, 2, 4, 8]
            self.blocks = nn.ModuleList(
                ResidualTCNBlock(channels[index], channels[index + 1], dilation)
                for index, dilation in enumerate(dilations)
            )
            self.classifier = nn.Sequential(
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(128, 1),
            )

        def forward(self, value: "torch.Tensor") -> "torch.Tensor":
            hidden = self.embedding(value).transpose(1, 2)
            for block in self.blocks:
                hidden = block(hidden)
            pooled = torch.cat((hidden.amax(dim=2), hidden.mean(dim=2)), dim=1)
            return self.classifier(pooled).squeeze(1)


    def export_onnx(model: "URLTCN", path: Path) -> None:
        model.eval()
        path.parent.mkdir(parents=True, exist_ok=True)
        sample = torch.zeros((1, MAX_URL_BYTES), dtype=torch.long)
        torch.onnx.export(
            model,
            sample,
            str(path),
            input_names=["url_bytes"],
            output_names=["logit"],
            dynamic_axes={"url_bytes": {0: "batch"}, "logit": {0: "batch"}},
            opset_version=14,
        )

except ImportError:  # pragma: no cover - optional training dependency
    URLTCN = None  # type: ignore

    def export_onnx(model: object, path: Path) -> None:
        raise RuntimeError("Install requirements-tcn.txt to export the URL TCN")


class ONNXTCNPredictor:
    def __init__(self, path: Path) -> None:
        import onnxruntime as ort

        self.session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        input_shape = self.session.get_inputs()[0].shape
        if len(input_shape) != 2 or input_shape[1] != MAX_URL_BYTES:
            raise ValueError(
                f"tcn_input_schema_mismatch: expected {MAX_URL_BYTES} bytes, graph has {input_shape}"
            )

    def predict(self, url: str) -> float:
        encoded = encode_url(url)[None, :]
        logit = float(self.session.run(["logit"], {"url_bytes": encoded})[0][0])
        return float(1.0 / (1.0 + np.exp(-np.clip(logit, -40.0, 40.0))))

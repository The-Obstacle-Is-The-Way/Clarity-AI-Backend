"""
Transformer-based symptom forecasting model for the NOVAMIND Digital Twin.

This module implements a Multi-Horizon Transformer with Quantile Regression
for psychiatric symptom forecasting, following the architecture described in
the AI Models Core Implementation documentation.
"""

from datetime import datetime
from typing import Any

import numpy as np

from app.domain.utils.datetime_utils import UTC

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except Exception:
    # PyTorch may not be available or may crash on import in certain environments
    torch = None
    nn = None
    F = None

# Removed import for ModelInferenceError as it is not available
# from app.domain.exceptions import ModelInferenceError


class MultiHeadAttention(nn.Module):
    """Multi-head attention module for the Transformer model."""

    def __init__(self, d_model: int, num_heads: int):
        """
        Initialize multi-head attention module.

        Args:
            d_model: Dimension of the model
            num_heads: Number of attention heads
        """
        super().__init__()
        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = d_model // num_heads

        self.query = nn.Linear(d_model, d_model)
        self.key = nn.Linear(d_model, d_model)
        self.value = nn.Linear(d_model, d_model)
        self.out = nn.Linear(d_model, d_model)

    def forward(
        self,
        query: "torch.Tensor",  # type: ignore
        key: "torch.Tensor",  # type: ignore
        value: "torch.Tensor",  # type: ignore
        mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Forward pass for multi-head attention.

        Args:
            query: Query tensor
            key: Key tensor
            value: Value tensor
            mask: Optional attention mask

        Returns:
            Output tensor after multi-head attention
        """
        batch_size = query.shape[0]

        # Linear projections and reshape for multi-head attention
        query = (
            self.query(query).view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        )
        key = self.key(key).view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        value = (
            self.value(value).view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        )

        # Scaled dot-product attention
        # Scaled dot-product attention
        scores = (
            torch.matmul(query, key.transpose(-2, -1))
            / torch.sqrt(torch.tensor(self.head_dim, dtype=torch.float32))
            if torch is not None
            else None
        )

        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)

        attention_weights = F.softmax(scores, dim=-1)
        attention_output = torch.matmul(attention_weights, value)

        # Reshape and project back
        attention_output = (
            attention_output.transpose(1, 2).contiguous().view(batch_size, -1, self.d_model)
        )
        return self.out(attention_output)


class TransformerEncoderLayer(nn.Module):
    """Transformer encoder layer."""

    def __init__(self, d_model: int, num_heads: int, d_ff: int, dropout: float = 0.1):
        """
        Initialize transformer encoder layer.

        Args:
            d_model: Dimension of the model
            num_heads: Number of attention heads
            d_ff: Dimension of the feed-forward network
            dropout: Dropout rate
        """
        super().__init__()
        self.self_attention = MultiHeadAttention(d_model, num_heads)
        self.feed_forward = nn.Sequential(
            nn.Linear(d_model, d_ff), nn.ReLU(), nn.Linear(d_ff, d_model)
        )
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        """
        Forward pass for transformer encoder layer.

        Args:
            x: Input tensor
            mask: Optional attention mask

        Returns:
            Output tensor after encoder layer
        """
        # Self-attention with residual connection and layer normalization
        attn_output = self.self_attention(x, x, x, mask)
        x = self.norm1(x + self.dropout(attn_output))

        # Feed-forward with residual connection and layer normalization
        ff_output = self.feed_forward(x)
        x = self.norm2(x + self.dropout(ff_output))

        return x


class TransformerDecoderLayer(nn.Module):
    """Transformer decoder layer."""

    def __init__(self, d_model: int, num_heads: int, d_ff: int, dropout: float = 0.1):
        """
        Initialize transformer decoder layer.

        Args:
            d_model: Dimension of the model
            num_heads: Number of attention heads
            d_ff: Dimension of the feed-forward network
            dropout: Dropout rate
        """
        super().__init__()
        self.self_attention = MultiHeadAttention(d_model, num_heads)
        self.cross_attention = MultiHeadAttention(d_model, num_heads)
        self.feed_forward = nn.Sequential(
            nn.Linear(d_model, d_ff), nn.ReLU(), nn.Linear(d_ff, d_model)
        )
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.norm3 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        x: torch.Tensor,
        encoder_output: torch.Tensor,
        src_mask: torch.Tensor | None = None,
        tgt_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Forward pass for transformer decoder layer.

        Args:
            x: Input tensor
            encoder_output: Output from the encoder
            src_mask: Source attention mask
            tgt_mask: Target attention mask

        Returns:
            Output tensor after decoder layer
        """
        # Self-attention with residual connection and layer normalization
        self_attn_output = self.self_attention(x, x, x, tgt_mask)
        x = self.norm1(x + self.dropout(self_attn_output))

        # Cross-attention with residual connection and layer normalization
        cross_attn_output = self.cross_attention(x, encoder_output, encoder_output, src_mask)
        x = self.norm2(x + self.dropout(cross_attn_output))

        # Feed-forward with residual connection and layer normalization
        ff_output = self.feed_forward(x)
        x = self.norm3(x + self.dropout(ff_output))

        return x


class QuantileOutput(nn.Module):
    """Quantile output layer for probabilistic forecasting."""

    def __init__(self, d_model: int, output_dim: int, quantiles: list[float]):
        """
        Initialize quantile output layer.

        Args:
            d_model: Dimension of the model
            output_dim: Dimension of the output
            quantiles: List of quantiles to predict
        """
        super().__init__()
        self.quantiles = quantiles
        self.num_quantiles = len(quantiles)
        self.output_dim = output_dim
        self.projection = nn.Linear(d_model, output_dim * self.num_quantiles)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass for quantile output layer.

        Args:
            x: Input tensor

        Returns:
            Output tensor with quantile predictions
        """
        batch_size = x.shape[0]
        seq_len = x.shape[1]

        # Project to output quantiles
        outputs = self.projection(x)
        outputs = outputs.view(batch_size, seq_len, self.output_dim, self.num_quantiles)

        return outputs


class MultiHorizonTransformer(nn.Module):
    """
    Multi-Horizon Transformer with Quantile Regression for psychiatric symptom forecasting.

    This model implements the state-of-the-art approach for time series forecasting
    with uncertainty quantification, as described in the AI Models Core Implementation.
    """

    def __init__(
        self,
        input_dim: int,
        output_dim: int,
        d_model: int = 256,
        num_heads: int = 8,
        num_encoder_layers: int = 6,
        num_decoder_layers: int = 6,
        d_ff: int = 1024,
        dropout: float = 0.1,
        quantiles: list[float] | None = None,
    ):
        """
        Initialize Multi-Horizon Transformer model.

        Args:
            input_dim: Dimension of the input features
            output_dim: Dimension of the output features
            d_model: Dimension of the model
            num_heads: Number of attention heads
            num_encoder_layers: Number of encoder layers
            num_decoder_layers: Number of decoder layers
            d_ff: Dimension of the feed-forward network
            dropout: Dropout rate
            quantiles: List of quantiles to predict
        """
        if quantiles is None:
            quantiles = [0.1, 0.5, 0.9]
        super().__init__()

        self.input_dim = input_dim
        self.output_dim = output_dim
        self.d_model = d_model
        self.quantiles = quantiles

        # Input embedding
        self.input_embedding = nn.Linear(input_dim, d_model)

        # Positional encoding
        self.positional_encoding = nn.Parameter(
            torch.zeros(1, 1000, d_model)
        )  # Max sequence length of 1000

        # Encoder layers
        self.encoder_layers = nn.ModuleList(
            [
                TransformerEncoderLayer(d_model, num_heads, d_ff, dropout)
                for _ in range(num_encoder_layers)
            ]
        )

        # Decoder layers
        self.decoder_layers = nn.ModuleList(
            [
                TransformerDecoderLayer(d_model, num_heads, d_ff, dropout)
                for _ in range(num_decoder_layers)
            ]
        )

        # Output layer
        self.output_layer = QuantileOutput(d_model, output_dim, quantiles)

        # Dropout
        self.dropout = nn.Dropout(dropout)

    def create_masks(
        self, src_seq: torch.Tensor, tgt_seq: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Create masks for the transformer.

        Args:
            src_seq: Source sequence
            tgt_seq: Target sequence

        Returns:
            Source mask and target mask
        """
        src_mask = torch.ones((src_seq.shape[0], 1, 1, src_seq.shape[1]), device=src_seq.device)

        # Create target mask (for autoregressive property)
        tgt_seq_len = tgt_seq.shape[1]
        tgt_mask = torch.tril(torch.ones((tgt_seq_len, tgt_seq_len), device=tgt_seq.device))
        tgt_mask = (
            tgt_mask.unsqueeze(0).unsqueeze(1).expand(tgt_seq.shape[0], 1, tgt_seq_len, tgt_seq_len)
        )

        return src_mask, tgt_mask

    def encode(self, src: torch.Tensor, src_mask: torch.Tensor | None = None) -> torch.Tensor:
        """
        Encode the source sequence.

        Args:
            src: Source sequence
            src_mask: Source mask

        Returns:
            Encoded representation
        """
        # Input embedding and positional encoding
        x = self.input_embedding(src)
        seq_len = x.shape[1]
        x = x + self.positional_encoding[:, :seq_len, :]
        x = self.dropout(x)

        # Pass through encoder layers
        for layer in self.encoder_layers:
            x = layer(x, src_mask)

        return x

    def decode(
        self,
        tgt: torch.Tensor,
        memory: torch.Tensor,
        src_mask: torch.Tensor | None = None,
        tgt_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Decode the target sequence.

        Args:
            tgt: Target sequence
            memory: Encoded source sequence
            src_mask: Source mask
            tgt_mask: Target mask

        Returns:
            Decoded representation
        """
        # Input embedding and positional encoding
        x = self.input_embedding(tgt)
        seq_len = x.shape[1]
        x = x + self.positional_encoding[:, :seq_len, :]
        x = self.dropout(x)

        # Pass through decoder layers
        for layer in self.decoder_layers:
            x = layer(x, memory, src_mask, tgt_mask)

        return x

    def forward(self, src: torch.Tensor, tgt: torch.Tensor) -> torch.Tensor:
        """
        Forward pass for the transformer model.

        Args:
            src: Source sequence
            tgt: Target sequence

        Returns:
            Output tensor with quantile predictions
        """
        src_mask, tgt_mask = self.create_masks(src, tgt)

        # Encode source sequence
        memory = self.encode(src, src_mask)

        # Decode target sequence
        output = self.decode(tgt, memory, src_mask, tgt_mask)

        # Generate quantile predictions
        return self.output_layer(output)

    async def predict(
        self,
        input_data: torch.Tensor,
        horizon: int,
        quantiles: list[float] | None = None,
    ) -> dict[str, Any]:
        """
        Generate predictions for the given input data.

        Args:
            input_data: Input tensor
            horizon: Forecast horizon
            quantiles: Optional list of quantiles to predict (defaults to model quantiles)

        Returns:
            Dictionary containing prediction results
        """
        try:
            # Set model to evaluation mode
            self.eval()

            # Use default quantiles if not provided
            if quantiles is None:
                quantiles = self.quantiles

            with torch.no_grad():
                # Initialize target with the last value of input
                tgt = input_data[:, -1:, :]

                # Generate predictions autoregressively
                all_preds = []
                for _ in range(horizon):
                    # Forward pass
                    output = self(input_data, tgt)

                    # Extract the last prediction
                    pred = output[:, -1:, :, :]
                    all_preds.append(pred)

                    # Update target for next step (using median prediction)
                    median_idx = self.quantiles.index(0.5)
                    next_step = pred[:, :, :, median_idx]
                    tgt = torch.cat([tgt, next_step], dim=1)

                # Concatenate all predictions
                all_preds = torch.cat(all_preds, dim=1)

                # Extract quantiles
                median_idx = self.quantiles.index(0.5)
                lower_idx = self.quantiles.index(min(self.quantiles))
                upper_idx = self.quantiles.index(max(self.quantiles))

                median_forecast = all_preds[:, :, :, median_idx].cpu().numpy()
                lower_bound = all_preds[:, :, :, lower_idx].cpu().numpy()
                upper_bound = all_preds[:, :, :, upper_idx].cpu().numpy()

                return {
                    "values": median_forecast,
                    "intervals": {"lower": lower_bound, "upper": upper_bound},
                    "all_quantiles": {
                        q: all_preds[:, :, :, i].cpu().numpy() for i, q in enumerate(self.quantiles)
                    },
                    "model_type": "transformer",
                }

        except Exception as e:
            raise Exception(f"Error during transformer model inference: {e!s}")


class SymptomTransformerModel:
    """
    High-level wrapper for the Multi-Horizon Transformer model.

    This class provides an interface for the domain layer to interact with
    the transformer model for symptom forecasting.
    """

    def __init__(
        self,
        model_path: str | None = None,
        input_dim: int = 20,
        output_dim: int = 10,
        device: str = "cuda" if torch.cuda.is_available() else "cpu",
    ):
        """
        Initialize the symptom transformer model.

        Args:
            model_path: Optional path to a pretrained model
            input_dim: Dimension of the input features
            output_dim: Dimension of the output features
            device: Device to run the model on
        """
        self.device = device
        self.model = MultiHorizonTransformer(
            input_dim=input_dim,
            output_dim=output_dim,
            d_model=256,
            num_heads=8,
            num_encoder_layers=6,
            num_decoder_layers=6,
            d_ff=1024,
            dropout=0.1,
            quantiles=[0.1, 0.5, 0.9],
        ).to(device)

        # Load pretrained model if provided
        if model_path:
            self.model.load_state_dict(torch.load(model_path, map_location=device, weights_only=True))

        self.model.eval()

    async def predict(
        self,
        input_data: np.ndarray,
        horizon: int,
        quantiles: list[float] | None = None,
    ) -> dict[str, Any]:
        """
        Generate predictions for the given input data.

        Args:
            input_data: Input numpy array
            horizon: Forecast horizon
            quantiles: Optional list of quantiles to predict

        Returns:
            Dictionary containing prediction results
        """
        # Convert numpy array to tensor
        input_tensor = torch.tensor(input_data, dtype=torch.float32).to(self.device)

        # Generate predictions
        return await self.model.predict(input_tensor, horizon, quantiles)

    def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the model.

        Returns:
            Dictionary containing model information
        """
        return {
            "model_type": "Multi-Horizon Transformer with Quantile Regression",
            "input_dim": self.model.input_dim,
            "output_dim": self.model.output_dim,
            "d_model": self.model.d_model,
            "quantiles": self.model.quantiles,
            "device": self.device,
            "parameter_count": sum(p.numel() for p in self.model.parameters()),
            "timestamp": datetime.now(UTC).isoformat(),
        }

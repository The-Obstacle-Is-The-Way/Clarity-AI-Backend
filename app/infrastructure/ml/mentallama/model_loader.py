# -*- coding: utf-8 -*-
"""
MentaLLaMA Model Loader.

This module provides functionality for loading and interacting with MentaLLaMA
models, handling text generation, and model management.
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

import aiohttp
import httpx
import numpy as np

# Use canonical config path
from app.config.settings import get_settings
settings = get_settings()
from app.core.exceptions.ml_exceptions import MentalLLaMAInferenceError, ModelLoadingError
from app.core.logging.phi_logger import get_phi_safe_logger

# Configure PHI-safe logger
logger = get_phi_safe_logger(__name__)


@dataclass
class GenerationParameters:
    """Parameters for text generation with LLM models."""
    
    temperature: float = 0.7
    max_tokens: int = 1024
    top_p: float = 0.95
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop_sequences: Optional[List[str]] = None
    system_prompt: Optional[str] = None


class MentaLLaMAModelLoader:
    """
    Loader for MentaLLaMA models.
    
    This class handles loading and interacting with MentaLLaMA models,
    providing a unified interface for text generation and model management.
    """
    
    def __init__(
        self,
        model_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        api_key: Optional[str] = None,
        inference_mode: str = "api",
        timeout: float = 60.0
    ):
        """
        Initialize MentaLLaMA Model Loader.
        
        Args:
            model_name: Name or path of the model to load
            endpoint_url: URL of the model API endpoint
            api_key: API key for authentication
            inference_mode: Mode for inference (api, local, sagemaker)
            timeout: Timeout for API requests in seconds
        """
        self.model_name = model_name or settings.MENTALLAMA_MODEL_NAME
        self.endpoint_url = endpoint_url or settings.MENTALLAMA_ENDPOINT_URL
        self.api_key = api_key or settings.MENTALLAMA_API_KEY
        self.inference_mode = inference_mode
        self.timeout = timeout
        
        self.client = None
        self.model = None
        self.tokenizer = None
        
        logger.info(f"MentaLLaMA Model Loader initialized with mode: {inference_mode}")
    
    async def load_model(self) -> None:
        """
        Load the model based on inference mode.
        
        Raises:
            ModelLoadingError: If model loading fails
        """
        if self.inference_mode == "local":
            await self._load_local_model()
        elif self.inference_mode == "sagemaker":
            await self._setup_sagemaker_client()
        else:  # Default to API
            await self._setup_api_client()
    
    async def _load_local_model(self) -> None:
        """
        Load model locally.
        
        Raises:
            ModelLoadingError: If model loading fails
        """
        try:
            # Dynamically import modules only when using local inference
            # to avoid unnecessary dependencies for API inference
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
            
            logger.info(f"Loading MentaLLaMA model locally: {self.model_name}")
            
            # Load model and tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            
            # Check if CUDA is available
            device = "cuda" if torch.cuda.is_available() else "cpu"
            torch_dtype = torch.float16 if device == "cuda" else torch.float32
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch_dtype,
                device_map=device,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            
            logger.info(f"MentaLLaMA model loaded locally on {device}")
            
        except Exception as e:
            error_msg = f"Failed to load MentaLLaMA model locally: {str(e)}"
            logger.error(error_msg)
            raise ModelLoadingError(error_msg)
    
    async def _setup_api_client(self) -> None:
        """
        Set up API client for remote inference.
        
        Raises:
            ModelLoadingError: If client setup fails
        """
        try:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            
            logger.info(f"API client set up for endpoint: {self.endpoint_url}")
            
        except Exception as e:
            error_msg = f"Failed to set up API client: {str(e)}"
            logger.error(error_msg)
            raise ModelLoadingError(error_msg)
    
    async def _setup_sagemaker_client(self) -> None:
        """
        Set up SageMaker client for AWS inference.
        
        Raises:
            ModelLoadingError: If client setup fails
        """
        try:
            # Import boto3 only when using SageMaker
            import boto3
            
            # Create SageMaker runtime client
            self.client = boto3.client('sagemaker-runtime')
            
            logger.info(f"SageMaker client set up for endpoint: {self.endpoint_url}")
            
        except Exception as e:
            error_msg = f"Failed to set up SageMaker client: {str(e)}"
            logger.error(error_msg)
            raise ModelLoadingError(error_msg)
    
    async def generate_text(
        self,
        prompt: str,
        params: Optional[GenerationParameters] = None,
        safety_filter: bool = True
    ) -> Dict[str, Any]:
        """
        Generate text using the model.
        
        Args:
            prompt: Input prompt for generation
            params: Generation parameters
            safety_filter: Whether to apply safety filtering
            
        Returns:
            Dictionary with generated text and metadata
            
        Raises:
            MentalLLaMAInferenceError: If text generation fails
        """
        if not prompt:
            raise MentalLLaMAInferenceError("Empty prompt provided for generation")
        
        # Use default parameters if not provided
        params = params or GenerationParameters()
        
        if self.inference_mode == "local":
            return await self._generate_text_local(prompt, params, safety_filter)
        elif self.inference_mode == "sagemaker":
            return await self._generate_text_sagemaker(prompt, params, safety_filter)
        else:  # Default to API
            return await self._generate_text_api(prompt, params, safety_filter)
    
    async def _generate_text_local(
        self,
        prompt: str,
        params: GenerationParameters,
        safety_filter: bool
    ) -> Dict[str, Any]:
        """
        Generate text using local model.
        
        Args:
            prompt: Input prompt for generation
            params: Generation parameters
            safety_filter: Whether to apply safety filtering
            
        Returns:
            Dictionary with generated text and metadata
            
        Raises:
            MentalLLaMAInferenceError: If text generation fails
        """
        try:
            import torch
            
            # Ensure model and tokenizer are loaded
            if self.model is None or self.tokenizer is None:
                await self._load_local_model()
            
            # Prepare the prompts - add system prompt if available
            if params.system_prompt:
                full_prompt = f"<s>[INST] <<SYS>>\n{params.system_prompt}\n<</SYS>>\n\n{prompt} [/INST]"
            else:
                full_prompt = f"<s>[INST] {prompt} [/INST]"
            
            # Tokenize the prompt
            inputs = self.tokenizer(full_prompt, return_tensors="pt")
            input_ids = inputs["input_ids"].to(self.model.device)
            
            # Set up generation parameters
            gen_config = {
                "max_new_tokens": params.max_tokens,
                "temperature": params.temperature,
                "top_p": params.top_p,
                "repetition_penalty": 1.0 + params.frequency_penalty,
                "do_sample": params.temperature > 0,
            }
            
            # Add stop sequences if provided
            if params.stop_sequences:
                gen_config["stop_sequences"] = params.stop_sequences
            
            # Generate
            generation_start = time.time()
            
            with torch.no_grad():
                output = self.model.generate(
                    input_ids,
                    **gen_config
                )
            
            # Decode the generated output
            generated_text = self.tokenizer.decode(
                output[0][len(input_ids[0]):], 
                skip_special_tokens=True
            )
            
            generation_time = time.time() - generation_start
            
            # Apply safety filter if requested
            filtered_text = generated_text
            safety_triggered = False
            
            if safety_filter:
                filtered_text, safety_triggered = self._apply_safety_filter(generated_text)
            
            return {
                "text": filtered_text,
                "model": self.model_name,
                "generation_time": generation_time,
                "prompt_tokens": len(inputs["input_ids"][0]),
                "completion_tokens": len(output[0]) - len(inputs["input_ids"][0]),
                "safety_triggered": safety_triggered,
                "original_text": generated_text if safety_triggered else None
            }
            
        except Exception as e:
            error_msg = f"Error during local text generation: {str(e)}"
            logger.error(error_msg)
            raise MentalLLaMAInferenceError(error_msg)
    
    async def _generate_text_api(
        self,
        prompt: str,
        params: GenerationParameters,
        safety_filter: bool
    ) -> Dict[str, Any]:
        """
        Generate text using API endpoint.
        
        Args:
            prompt: Input prompt for generation
            params: Generation parameters
            safety_filter: Whether to apply safety filtering
            
        Returns:
            Dictionary with generated text and metadata
            
        Raises:
            MentalLLaMAInferenceError: If text generation fails
        """
        try:
            # Ensure client is set up
            if self.client is None:
                await self._setup_api_client()
            
            # Prepare request payload
            request_payload = {
                "prompt": prompt,
                "max_tokens": params.max_tokens,
                "temperature": params.temperature,
                "top_p": params.top_p,
                "frequency_penalty": params.frequency_penalty,
                "presence_penalty": params.presence_penalty,
                "safety_filter": safety_filter
            }
            
            # Add system prompt if available
            if params.system_prompt:
                request_payload["system"] = params.system_prompt
            
            # Add stop sequences if available
            if params.stop_sequences:
                request_payload["stop"] = params.stop_sequences
            
            # Make API request
            generation_start = time.time()
            
            response = await self.client.post(
                self.endpoint_url,
                json=request_payload
            )
            
            generation_time = time.time() - generation_start
            
            # Check for successful response
            if response.status_code != 200:
                error_msg = f"API returned error: {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise MentalLLaMAInferenceError(error_msg)
            
            # Parse response
            response_data = response.json()
            
            if "text" not in response_data:
                error_msg = "API response missing 'text' field"
                logger.error(error_msg)
                raise MentalLLaMAInferenceError(error_msg)
            
            # Extract response data with defaults for missing fields
            result = {
                "text": response_data["text"],
                "model": response_data.get("model", self.model_name),
                "generation_time": generation_time,
                "prompt_tokens": response_data.get("prompt_tokens", 0),
                "completion_tokens": response_data.get("completion_tokens", 0),
                "safety_triggered": response_data.get("safety_triggered", False),
                "original_text": response_data.get("original_text")
            }
            
            return result
            
        except Exception as e:
            error_msg = f"Error during API text generation: {str(e)}"
            logger.error(error_msg)
            raise MentalLLaMAInferenceError(error_msg)
    
    async def _generate_text_sagemaker(
        self,
        prompt: str,
        params: GenerationParameters,
        safety_filter: bool
    ) -> Dict[str, Any]:
        """
        Generate text using SageMaker endpoint.
        
        Args:
            prompt: Input prompt for generation
            params: Generation parameters
            safety_filter: Whether to apply safety filtering
            
        Returns:
            Dictionary with generated text and metadata
            
        Raises:
            MentalLLaMAInferenceError: If text generation fails
        """
        try:
            # Ensure client is set up
            if self.client is None:
                await self._setup_sagemaker_client()
            
            # Prepare request payload
            request_payload = {
                "prompt": prompt,
                "max_tokens": params.max_tokens,
                "temperature": params.temperature,
                "top_p": params.top_p,
                "frequency_penalty": params.frequency_penalty,
                "presence_penalty": params.presence_penalty,
                "safety_filter": safety_filter
            }
            
            # Add system prompt if available
            if params.system_prompt:
                request_payload["system"] = params.system_prompt
            
            # Add stop sequences if available
            if params.stop_sequences:
                request_payload["stop"] = params.stop_sequences
            
            # Make SageMaker request
            generation_start = time.time()
            
            # SageMaker calls need to be run in an executor to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.client.invoke_endpoint(
                    EndpointName=self.endpoint_url,
                    ContentType='application/json',
                    Body=json.dumps(request_payload)
                )
            )
            
            generation_time = time.time() - generation_start
            
            # Parse response
            response_body = response['Body'].read().decode('utf-8')
            response_data = json.loads(response_body)
            
            if "text" not in response_data:
                error_msg = "SageMaker response missing 'text' field"
                logger.error(error_msg)
                raise MentalLLaMAInferenceError(error_msg)
            
            # Extract response data with defaults for missing fields
            result = {
                "text": response_data["text"],
                "model": response_data.get("model", self.model_name),
                "generation_time": generation_time,
                "prompt_tokens": response_data.get("prompt_tokens", 0),
                "completion_tokens": response_data.get("completion_tokens", 0),
                "safety_triggered": response_data.get("safety_triggered", False),
                "original_text": response_data.get("original_text")
            }
            
            return result
            
        except Exception as e:
            error_msg = f"Error during SageMaker text generation: {str(e)}"
            logger.error(error_msg)
            raise MentalLLaMAInferenceError(error_msg)
    
    def _apply_safety_filter(self, text: str) -> Tuple[str, bool]:
        """
        Apply safety filter to generated text.
        
        Args:
            text: Text to filter
            
        Returns:
            Tuple of (filtered_text, safety_triggered)
        """
        # This is a simple example - in a production system,
        # this would be a more sophisticated content filtering approach
        
        # Define inappropriate content patterns
        inappropriate_patterns = [
            "harm yourself",
            "commit suicide",
            "harm others",
            "illegal drugs",
            "illegal activities"
        ]
        
        # Check if any patterns are present
        safety_triggered = any(pattern in text.lower() for pattern in inappropriate_patterns)
        
        if safety_triggered:
            # Replace with safe content
            filtered_text = (
                "I apologize, but I cannot provide that information as it may not be "
                "safe or appropriate for clinical use. Please consult with a licensed "
                "healthcare professional for personalized medical advice."
            )
            logger.warning("Safety filter triggered during text generation")
            return filtered_text, True
        
        return text, False
    
    async def close(self) -> None:
        """Close the model and clean up resources."""
        if self.client and hasattr(self.client, "aclose"):
            await self.client.aclose()
        
        # Clear model from memory if loaded locally
        if self.model is not None:
            self.model = None
            self.tokenizer = None
            
            # Force garbage collection
            import gc
            gc.collect()
            
            # Force CUDA cache clear if available
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except ImportError:
                pass
            
            logger.info("MentaLLaMA model unloaded and resources cleaned up")
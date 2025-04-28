# -*- coding: utf-8 -*-
"""
AWS Bedrock MentaLLaMA Implementation.

This module provides an AWS Bedrock implementation of MentaLLaMA services.
"""

import json
import time
from typing import Any, Dict, List, Optional, Union

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = Exception

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
# Corrected import path for the base MentaLLaMA implementation
from app.infrastructure.ml.mentallama.service import MentaLLaMA as BaseMentaLLaMA
from app.core.utils.logging import get_logger


# Create logger (no PHI logging)
logger = get_logger(__name__)


class AWSBedrockMentaLLaMA(BaseMentaLLaMA):
    """
    AWS Bedrock implementation of MentaLLaMA service.
    
    This implementation uses AWS Bedrock for foundation models like Claude and Titan.
    """
    
    def _initialize_provider(self) -> None:
        """
        Initialize AWS Bedrock provider.
        
        Sets up AWS Bedrock client, available models, and model mappings.
        
        Raises:
            InvalidConfigurationError: If AWS Bedrock initialization fails
        """
        try:
            if boto3 is None:
                raise ImportError("boto3 is required for AWS Bedrock support")
            
            # Get AWS credentials from config
            region = self._get_config_param("aws_region", "us-east-1")
            aws_access_key = self._get_config_param("aws_access_key_id")
            aws_secret_key = self._get_config_param("aws_secret_access_key")
            aws_session_token = self._get_config_param("aws_session_token")
            
            # Create boto3 session
            session_params = {}
            if aws_access_key and aws_secret_key:
                session_params.update({
                    "aws_access_key_id": aws_access_key,
                    "aws_secret_access_key": aws_secret_key
                })
                if aws_session_token:
                    session_params["aws_session_token"] = aws_session_token
            
            session = boto3.Session(**session_params)
            
            # Create Bedrock client
            self._bedrock_client = session.client(
                service_name="bedrock-runtime",
                region_name=region
            )
            
            # Set up available models
            self._available_models = self._discover_available_models()
            
            # Set up model mappings for tasks
            self._model_mappings = {
                "default": self._get_config_param("default_model", "anthropic.claude-3-haiku-20240307-v1:0"),
                "depression_detection": self._get_config_param("depression_detection_model", "anthropic.claude-3-haiku-20240307-v1:0"),
                "risk_assessment": self._get_config_param("risk_assessment_model", "anthropic.claude-3-opus-20240229-v1:0"),
                "sentiment_analysis": self._get_config_param("sentiment_analysis_model", "anthropic.claude-3-haiku-20240307-v1:0"),
                "wellness_dimensions": self._get_config_param("wellness_dimensions_model", "anthropic.claude-3-sonnet-20240229-v1:0"),
            }
            
            logger.info("AWS Bedrock MentaLLaMA provider initialized")
            
        except ClientError as e:
            logger.error(f"AWS Bedrock client error: {str(e)}")
            raise InvalidConfigurationError(f"AWS Bedrock client error: {str(e)}")
        except ImportError as e:
            logger.error(f"Import error: {str(e)}")
            raise InvalidConfigurationError(f"Import error: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS Bedrock provider: {str(e)}")
            raise InvalidConfigurationError(f"Failed to initialize AWS Bedrock provider: {str(e)}")
    
    def _discover_available_models(self) -> Dict[str, Dict[str, Any]]:
        """
        Discover available models from AWS Bedrock.
        
        Returns:
            Dict of model IDs to model information
        """
        # These models are hardcoded for now since Bedrock doesn't have a simple
        # API for listing available models with their capabilities
        models = {
            "anthropic.claude-3-haiku-20240307-v1:0": {
                "name": "Claude 3 Haiku",
                "provider": "Anthropic",
                "description": "Fast and affordable model for simple tasks",
                "max_tokens": 200000,
                "capabilities": ["text_generation", "text_analysis"]
            },
            "anthropic.claude-3-sonnet-20240229-v1:0": {
                "name": "Claude 3 Sonnet",
                "provider": "Anthropic",
                "description": "Balanced model for most tasks",
                "max_tokens": 200000,
                "capabilities": ["text_generation", "text_analysis"]
            },
            "anthropic.claude-3-opus-20240229-v1:0": {
                "name": "Claude 3 Opus",
                "provider": "Anthropic",
                "description": "Most powerful and capable model",
                "max_tokens": 200000,
                "capabilities": ["text_generation", "text_analysis"]
            },
            "amazon.titan-text-express-v1": {
                "name": "Titan Text Express",
                "provider": "Amazon",
                "description": "General purpose text model for various tasks",
                "max_tokens": 8000,
                "capabilities": ["text_generation", "text_analysis"]
            },
            "amazon.titan-text-lite-v1": {
                "name": "Titan Text Lite",
                "provider": "Amazon",
                "description": "Lightweight text model for simple tasks",
                "max_tokens": 4000,
                "capabilities": ["text_generation", "text_analysis"]
            }
        }
        
        return models
    
    def _generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate text using AWS Bedrock models.
        
        Args:
            prompt: Input prompt
            model: Model to use
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters
            
        Returns:
            Dict containing generated text and metadata
            
        Raises:
            ModelNotFoundError: If model is not available
            ServiceUnavailableError: If service is unavailable
            InvalidRequestError: If request is invalid
        """
        if not model:
            model = self._model_mappings["default"]
        
        if model not in self._available_models:
            raise ModelNotFoundError(f"Model '{model}' not found")
        
        model_info = self._available_models[model]
        
        # Set defaults if not provided
        max_tokens = max_tokens or 1024
        temperature = temperature if temperature is not None else 0.7
        
        try:
            # Prepare request based on model provider
            if "anthropic" in model.lower():
                response = self._generate_anthropic(
                    model=model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs
                )
            elif "amazon" in model.lower():
                response = self._generate_amazon(
                    model=model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs
                )
            else:
                raise InvalidRequestError(f"Unsupported model provider for model '{model}'")
            
            # Extract the text from the response
            text = self._extract_text_from_response(response, model)
            
            # Create result
            result = {
                "text": text,
                "processing_time": response.get("processing_time", 0.0),
                "tokens_used": response.get("tokens_used", 0),
                "metadata": {
                    "provider": model_info.get("provider", "AWS"),
                    "model": model,
                    "confidence": response.get("confidence", 0.8),
                }
            }
            
            return result
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"AWS Bedrock error: {error_code} - {error_message}")
            
            if error_code == "ValidationException":
                raise InvalidRequestError(f"Invalid request: {error_message}")
            elif error_code == "ResourceNotFoundException":
                raise ModelNotFoundError(f"Model not found: {error_message}")
            elif error_code in ["ThrottlingException", "ServiceUnavailableException"]:
                raise ServiceUnavailableError(f"Service unavailable: {error_message}")
            else:
                raise ServiceUnavailableError(f"AWS Bedrock error: {error_message}")
        except Exception as e:
            logger.error(f"Error generating text: {str(e)}")
            raise ServiceUnavailableError(f"Error generating text: {str(e)}")
    
    def _generate_anthropic(
        self,
        model: str,
        prompt: str,
        max_tokens: int,
        temperature: float,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate text using Anthropic Claude models.
        
        Args:
            model: Model ID
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters
            
        Returns:
            Dict containing response data
        """
        start_time = time.time()
        
        # Build request body
        # Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-claude.html
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        # Add optional parameters if provided
        top_p = kwargs.get("top_p")
        if top_p is not None:
            request_body["top_p"] = top_p
        
        top_k = kwargs.get("top_k")
        if top_k is not None:
            request_body["top_k"] = top_k
        
        # Invoke model
        response = self._bedrock_client.invoke_model(
            modelId=model,
            body=json.dumps(request_body)
        )
        
        # Process response
        response_body = json.loads(response.get("body").read())
        content = response_body.get("content", [])
        text = ""
        
        # Extract text content
        for item in content:
            if item.get("type") == "text":
                text += item.get("text", "")
        
        # Get usage information
        usage = response_body.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Create result
        result = {
            "raw_response": response_body,
            "text": text,
            "processing_time": processing_time,
            "tokens_used": input_tokens + output_tokens,
            "confidence": 0.9  # Claude doesn't provide confidence scores
        }
        
        return result
    
    def _generate_amazon(
        self,
        model: str,
        prompt: str,
        max_tokens: int,
        temperature: float,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate text using Amazon Titan models.
        
        Args:
            model: Model ID
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters
            
        Returns:
            Dict containing response data
        """
        start_time = time.time()
        
        # Build request body
        # Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-titan-text.html
        request_body = {
            "inputText": prompt,
            "textGenerationConfig": {
                "maxTokenCount": max_tokens,
                "temperature": temperature,
                "stopSequences": kwargs.get("stop_sequences", [])
            }
        }
        
        # Add optional parameters if provided
        top_p = kwargs.get("top_p")
        if top_p is not None:
            request_body["textGenerationConfig"]["topP"] = top_p
        
        # Invoke model
        response = self._bedrock_client.invoke_model(
            modelId=model,
            body=json.dumps(request_body)
        )
        
        # Process response
        response_body = json.loads(response.get("body").read())
        text = response_body.get("results", [{}])[0].get("outputText", "")
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Create result
        result = {
            "raw_response": response_body,
            "text": text,
            "processing_time": processing_time,
            "tokens_used": len(prompt.split()) + len(text.split()),  # Approximate token count
            "confidence": 0.85  # Titan doesn't provide confidence scores
        }
        
        return result
    
    def _extract_text_from_response(self, response: Dict[str, Any], model: str) -> str:
        """
        Extract text from model response.
        
        Args:
            response: Model response
            model: Model ID
            
        Returns:
            Extracted text
        """
        # Handle different model responses
        if "anthropic" in model.lower():
            return response.get("text", "")
        elif "amazon" in model.lower():
            return response.get("text", "")
        else:
            # Default fallback
            raw_response = response.get("raw_response", {})
            if isinstance(raw_response, dict):
                # Try common response formats
                if "text" in raw_response:
                    return raw_response["text"]
                elif "content" in raw_response:
                    return raw_response["content"]
                elif "output" in raw_response:
                    return raw_response["output"]
                elif "generated_text" in raw_response:
                    return raw_response["generated_text"]
            
            # Final fallback to empty string
            return ""
    
    def digital_twin_conversation(
        self,
        prompt: str,
        patient_id: str,
        session_id: Optional[str] = None,
        model: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Conduct a conversation with a patient's digital twin.
        
        Args:
            prompt: Text prompt for the conversation
            patient_id: Patient ID
            session_id: Optional session ID for continued conversations
            model: Optional model to use
            context: Optional context for the conversation
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters
            
        Returns:
            Dict containing digital twin conversation results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            ModelNotFoundError: If model cannot be resolved
        """
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service is not initialized")
        
        try:
            # Get model to use (prefer digital twin specific model if configured)
            dt_model = self._get_config_param("digital_twin_model")
            model_to_use = self._resolve_model(model or dt_model)
            
            # Get history from context if provided
            history = context.get("history", []) if context else []
            
            # Create system prompt with patient context
            system_prompt = self._create_digital_twin_system_prompt(patient_id, context)
            
            # Prepare full prompt with history and user message
            full_prompt = self._create_digital_twin_conversation_prompt(
                system_prompt=system_prompt,
                history=history,
                user_message=prompt
            )
            
            # Set parameters
            max_tokens = max_tokens or self._get_config_param("max_tokens", 1024)
            temperature = temperature or self._get_config_param("temperature", 0.7)
            
            # Generate response
            result = self._generate(
                prompt=full_prompt,
                model=model_to_use,
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
            
            # Create response
            response = {
                "text": result.get("text", ""),
                "patient_id": patient_id,
                "session_id": session_id,
                "processing_time": result.get("processing_time", 0.0),
                "tokens_used": result.get("tokens_used", 0),
                "metadata": result.get("metadata", {})
            }
            
            return response
            
        except Exception as e:
            logger.error(f"Error in digital twin conversation: {str(e)}")
            raise
    
    def _create_digital_twin_system_prompt(
        self,
        patient_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a system prompt for digital twin conversation.
        
        Args:
            patient_id: Patient ID
            context: Optional context for the conversation
            
        Returns:
            System prompt for digital twin conversation
        """
        # Extract patient information from context
        patient_info = context.get("patient_info", {}) if context else {}
        name = patient_info.get("name", "[Patient Name]")
        age = patient_info.get("age", "[Age]")
        gender = patient_info.get("gender", "[Gender]")
        diagnosis = patient_info.get("diagnosis", "")
        medications = patient_info.get("medications", [])
        treatment_plan = patient_info.get("treatment_plan", "")
        
        # Build system prompt
        system_prompt = f"""You are a digital health assistant for a patient with the following profile:
Patient ID: {patient_id}
Name: {name}
Age: {age}
Gender: {gender}
"""
        
        if diagnosis:
            system_prompt += f"Diagnosis: {diagnosis}\n"
        
        if medications:
            system_prompt += "Medications:\n"
            for med in medications:
                system_prompt += f"- {med}\n"
        
        if treatment_plan:
            system_prompt += f"Treatment Plan: {treatment_plan}\n"
        
        system_prompt += """
Your role is to provide supportive, empathetic communication while helping the patient adhere to their treatment plan and providing information about their care. 

You should:
1. Respond in a warm, professional manner
2. Provide accurate health information based on the patient's profile
3. Help the patient navigate their treatment plan
4. Recognize when to escalate concerns to a healthcare provider
5. Maintain a supportive and encouraging tone

You should NOT:
1. Provide medical advice that contradicts their doctor's recommendations
2. Make definitive diagnoses
3. Recommend changes to medications or treatment plans
4. Dismiss or minimize the patient's concerns
5. Use overly technical language that may be difficult to understand

This conversation is HIPAA-compliant and secure.
"""
        
        return system_prompt
    
    def _create_digital_twin_conversation_prompt(
        self,
        system_prompt: str,
        history: List[Dict[str, Any]],
        user_message: str
    ) -> str:
        """
        Create a conversation prompt for digital twin.
        
        Args:
            system_prompt: System prompt
            history: Conversation history
            user_message: Current user message
            
        Returns:
            Full conversation prompt
        """
        prompt = f"""<system>
{system_prompt}
</system>

"""
        
        # Add conversation history
        for entry in history:
            role = entry.get("role", "")
            content = entry.get("content", "")
            
            if role == "user":
                prompt += f"Human: {content}\n\n"
            elif role == "assistant":
                prompt += f"Assistant: {content}\n\n"
        
        # Add current user message
        prompt += f"Human: {user_message}\n\nAssistant:"
        
        return prompt

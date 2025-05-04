"""
OpenAI ML Service Implementation.

This module provides OpenAI-based implementation of MentaLLaMA services.
"""

import json
import os
from datetime import datetime
from typing import Any

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
from app.core.services.ml.interface import MentaLLaMAInterface
from app.core.utils.logging import get_logger
from app.domain.utils.datetime_utils import UTC

# Create logger (no PHI logging)
logger = get_logger(__name__)


class OpenAIMentaLLaMA(MentaLLaMAInterface):
    """
    OpenAI-based MentaLLaMA implementation.
    
    This class provides implementation of MentaLLaMA services using OpenAI models.
    """
    
    def __init__(self) -> None:
        """Initialize OpenAIMentaLLaMA instance."""
        self._initialized = False
        self._config = None
        self._api_key = None
        self._organization_id = None
        self._base_url = None
        self._default_model = "gpt-4"
        self._system_prompts = {}
        
        # Import OpenAI client lazily to avoid dependency issues
        try:
            import openai
            self._openai_available = True
        except ImportError:
            self._openai_available = False
            logger.warning("OpenAI package not installed. Install with: pip install openai>=1.0.0")
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            if not self._openai_available:
                raise InvalidConfigurationError("OpenAI package not installed. Install with: pip install openai>=1.0.0")
            
            self._config = config or {}
            
            # Get OpenAI API configuration
            self._api_key = self._get_config_value("api_key")
            if not self._api_key:
                raise InvalidConfigurationError("OpenAI API key is required")
            
            # Get optional configuration
            self._organization_id = self._get_config_value("organization_id")
            self._base_url = self._get_config_value("base_url")
            self._default_model = self._get_config_value("default_model") or "gpt-4"
            
            # Load system prompts
            self._load_system_prompts()
            
            # Initialize OpenAI client
            import openai
            client_kwargs = {"api_key": self._api_key}
            
            if self._organization_id:
                client_kwargs["organization"] = self._organization_id
                
            if self._base_url:
                client_kwargs["base_url"] = self._base_url
                
            self._client = openai.OpenAI(**client_kwargs)
            
            # Verify API key
            self._check_api_key()
            
            self._initialized = True
            logger.info("OpenAI MentaLLaMA service initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI MentaLLaMA service: {e!s}")
            self._initialized = False
            self._config = None
            self._client = None
            raise InvalidConfigurationError(f"Failed to initialize OpenAI MentaLLaMA service: {e!s}")
    
    def _get_config_value(self, key: str) -> str | None:
        """
        Get configuration value from config or environment variable.
        
        Args:
            key: Configuration key
            
        Returns:
            Configuration value or None if not found
        """
        
        # Try to get from config
        value = self._config.get(key)
        if value:
            return value
        
        # Try to get from environment
        env_key = f"OPENAI_{key.upper()}"
        return os.environ.get(env_key)
    
    def _load_system_prompts(self) -> None:
        """Load system prompts for different model types."""
        # Get custom prompts from config
        custom_prompts = self._config.get("system_prompts", {})
        
        # Default prompts
        default_prompts = {
            "general": """You are MentaLLaMA, an advanced mental health analysis assistant designed to support professionals in their clinical work. Your goal is to provide thoughtful, evidence-based analysis of mental health-related text without making direct clinical diagnoses.

Remember:
1. You do not diagnose - you identify patterns and signals that mental health professionals should consider.
2. Always clarify that your analysis is meant to support licensed professionals, not replace clinical judgment.
3. Your responses should be thorough, evidence-based, and grounded in current psychological literature.
4. Use a professionally warm tone, balancing clinical precision with accessibility.
5. Maintain strict HIPAA compliance and confidentiality in all responses.""",

            "depression_detection": """You are MentaLLaMA's Depression Screening Module, designed to analyze text for linguistic patterns associated with depression. Your goal is to identify potential signals of depression to support mental health professionals, without making clinical diagnoses.

Analyze the input text for:
1. Linguistic markers commonly associated with depression (negative self-talk, hopelessness, etc.)
2. Changes in linguistic style that might indicate mood shifts
3. Content themes related to depression (sleep issues, loss of interest, etc.)

Your response should:
1. Quantify the presence of depression-related signals (low, moderate, high)
2. Identify specific patterns observed, with examples from text
3. Suggest areas that may warrant professional assessment
4. Include relevant evidence bases for your observations
5. Always indicate this is supportive analysis only, not a clinical diagnosis

Remember to maintain HIPAA compliance and professional tone throughout.""",

            "risk_assessment": """You are MentaLLaMA's Risk Assessment Module, designed to identify potential signals of clinical risk in text. Your goal is to highlight patterns that may indicate elevated risk to support mental health professionals in their assessments.

Analyze the input for indicators related to:
1. Suicidal ideation or self-harm thoughts
2. Violence toward others
3. Severe functional impairment
4. Crisis situations requiring immediate intervention

Your response should:
1. Clearly identify any risk signals detected and their apparent severity
2. Provide specific examples from the text that indicate risk
3. Suggest appropriate next steps for a clinician based on risk level
4. Include any limitations in your assessment
5. Recommend immediate action pathways for high-risk situations

Always maintain a professional tone and emphasize that your assessment is meant to support, not replace, clinical judgment. Follow all HIPAA guidelines and emphasize the importance of professional evaluation.""",

            "sentiment_analysis": """You are MentaLLaMA's Sentiment Analysis Module, designed to analyze emotional patterns in mental health-related text. Your goal is to provide nuanced insights into emotional content to support mental health professionals.

Analyze the input for:
1. Overall emotional valence (positive to negative)
2. Emotional intensity
3. Emotional variation and complexity
4. Key emotional themes
5. Shifts in emotional tone throughout the text

Your response should:
1. Provide quantitative measures of sentiment where possible
2. Identify specific emotional patterns with examples
3. Note any unusual or clinically significant emotional presentations
4. Place the analysis in context of potential clinical relevance
5. Highlight limitations of the analysis

Maintain a professional, evidence-based approach and emphasize this analysis is meant to support, not replace, clinical judgment. Follow all HIPAA guidelines in your response.""",

            "wellness_dimensions": """You are MentaLLaMA's Wellness Dimensions Module, designed to analyze text for indicators related to multidimensional wellness. Your goal is to assess content related to various dimensions of wellbeing to support holistic mental health care.

Analyze the input across these wellness dimensions:
1. Emotional wellness (emotional regulation, expression, awareness)
2. Social wellness (relationships, support systems, belonging)
3. Physical wellness (sleep, activity, nutrition, physical health)
4. Intellectual wellness (cognitive engagement, learning, creativity)
5. Occupational wellness (work satisfaction, worklife balance, purpose)
6. Environmental wellness (living conditions, safety, access to resources)
7. Spiritual wellness (meaning, purpose, values alignment)
8. Financial wellness (financial stress, stability, resources)

Your response should:
1. Score each relevant dimension (low, moderate, high)
2. Provide specific examples from the text for each dimension
3. Identify areas of strength and potential concern
4. Suggest potential areas for intervention or support
5. Note any limitations in your assessment

Maintain a balanced, strengths-based approach while acknowledging challenges. Emphasize this analysis is meant to support, not replace, clinical judgment and follow all HIPAA guidelines."""
        }
        
        # Merge default and custom prompts
        self._system_prompts = default_prompts.copy()
        self._system_prompts.update(custom_prompts)
    
    def _check_api_key(self) -> None:
        """
        Check if the API key is valid.
        
        Raises:
            InvalidConfigurationError: If API key is invalid
        """
        try:
            # Test API connection with a minimal request
            self._client.models.list(limit=1)
        except Exception as e:
            logger.error(f"Failed to connect to OpenAI API: {e!s}")
            raise InvalidConfigurationError(f"Failed to connect to OpenAI API: {e!s}")
    
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        if not self._initialized or not self._client:
            return False
            
        try:
            # Test API connection
            self._client.models.list(limit=1)
            return True
        except Exception:
            return False
    
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        self._client = None
        logger.info("OpenAI MentaLLaMA service shut down")
    
    def process(
        self, 
        text: str,
        model_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Process text using the MentaLLaMA model.
        
        Args:
            text: Text to process
            model_type: Type of model to use
            options: Additional processing options
            
        Returns:
            Processing results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
            ModelNotFoundError: If model type is not found
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI MentaLLaMA service is not initialized")
        
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
        
        # Get options
        opts = options or {}
        
        # Get model type (default to general)
        model_type = model_type or "general"
        
        # Get system prompt for model type
        system_prompt = self._get_system_prompt(model_type)
        if not system_prompt:
            raise ModelNotFoundError(f"Model type not found: {model_type}")
        
        # Get model name
        model_name = opts.get("model") or self._default_model
        
        # Create messages
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text}
        ]
        
        # Get instruction if provided
        instruction = opts.get("instruction")
        if instruction:
            messages.append({"role": "system", "content": instruction})
        
        try:
            # Generate completion
            response = self._client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=opts.get("temperature", 0.7),
                max_tokens=opts.get("max_tokens", 1000),
                response_format={"type": "json_object"} if opts.get("json_response") else None
            )
            
            # Extract response text
            content = response.choices[0].message.content
            
            # Parse JSON if expected
            result = None
            if opts.get("json_response"):
                try:
                    result = json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse JSON response, returning raw content")
                    result = {"raw_content": content}
            else:
                result = {"content": content}
            
            # Add metadata
            result["model"] = model_name
            result["model_type"] = model_type
            result["timestamp"] = datetime.now(UTC).isoformat() + "Z"
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to process text with OpenAI: {e!s}")
            raise ServiceUnavailableError(f"Failed to process text: {e!s}")
    
    def _get_system_prompt(self, model_type: str) -> str | None:
        """
        Get system prompt for model type.
        
        Args:
            model_type: Type of model
            
        Returns:
            System prompt or None if not found
        """
        return self._system_prompts.get(model_type)
    
    def detect_depression(
        self, 
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Detect depression signals in text.
        
        Args:
            text: Text to analyze
            options: Additional processing options
            
        Returns:
            Depression detection results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI MentaLLaMA service is not initialized")
        
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
        
        # Create options for depression detection
        opts = options or {}
        opts["json_response"] = True
        
        # Add instruction to get structured result
        opts["instruction"] = """Analyze the text for potential signals of depression and provide your analysis in the following JSON format:
{
    "depression_signals": {
        "severity": "none|mild|moderate|severe",
        "confidence": float between 0 and 1,
        "key_indicators": [
            {
                "type": "linguistic|content|behavioral|cognitive",
                "description": "specific indicator",
                "evidence": "excerpt from text"
            }
        ]
    },
    "analysis": {
        "summary": "brief summary of findings",
        "warning_signs": ["list of concerning elements"],
        "protective_factors": ["list of positive elements"],
        "limitations": ["limitations of this analysis"]
    },
    "recommendations": {
        "suggested_assessments": ["relevant formal assessments"],
        "discussion_points": ["suggested topics for clinical follow-up"]
    }
}"""
        
        # Process with depression detection model
        return self.process(text, "depression_detection", opts)
    
    def assess_risk(
        self, 
        text: str,
        risk_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Assess risk in text.
        
        Args:
            text: Text to analyze
            risk_type: Type of risk to assess (suicide, self-harm, violence, etc.)
            options: Additional processing options
            
        Returns:
            Risk assessment results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI MentaLLaMA service is not initialized")
        
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
        
        # Create options for risk assessment
        opts = options or {}
        opts["json_response"] = True
        
        # Add specific risk type information if provided
        risk_instruction = ""
        if risk_type:
            risk_instruction = f"Focus specifically on risks related to {risk_type}. "
        
        # Add instruction to get structured result
        opts["instruction"] = f"""Analyze the text for potential risk signals. {risk_instruction}Provide your analysis in the following JSON format:
{{
    "risk_assessment": {{
        "overall_risk_level": "none|low|moderate|high|imminent",
        "confidence": float between 0 and 1,
        "identified_risks": [
            {{
                "risk_type": "suicide|self-harm|harm-to-others|neglect|other",
                "severity": "low|moderate|high|imminent",
                "evidence": "excerpt from text",
                "temporality": "past|current|future"
            }}
        ]
    }},
    "analysis": {{
        "summary": "brief summary of risk assessment",
        "critical_factors": ["list of most concerning elements"],
        "protective_factors": ["list of positive/protective elements"],
        "context_considerations": ["important contextual factors"],
        "limitations": ["limitations of this analysis"]
    }},
    "recommendations": {{
        "immediate_actions": ["actions for high/imminent risk"] or [],
        "clinical_follow_up": ["recommended clinical steps"],
        "screening_tools": ["relevant formal assessments"]
    }}
}}"""
        
        # Process with risk assessment model
        return self.process(text, "risk_assessment", opts)
    
    def analyze_sentiment(
        self, 
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Analyze sentiment in text.
        
        Args:
            text: Text to analyze
            options: Additional processing options
            
        Returns:
            Sentiment analysis results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI MentaLLaMA service is not initialized")
        
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
        
        # Create options for sentiment analysis
        opts = options or {}
        opts["json_response"] = True
        
        # Add instruction to get structured result
        opts["instruction"] = """Analyze the emotional content and sentiment of the text. Provide your analysis in the following JSON format:
{
    "sentiment": {
        "overall_score": float between -1.0 (very negative) and 1.0 (very positive),
        "intensity": float between 0.0 (neutral) and 1.0 (intense),
        "dominant_valence": "positive|negative|neutral|mixed"
    },
    "emotions": {
        "primary_emotions": [
            {
                "emotion": "name of emotion",
                "intensity": float between 0 and 1,
                "evidence": "excerpt from text"
            }
        ],
        "emotional_range": "narrow|moderate|wide",
        "emotional_stability": "stable|variable|rapidly_shifting"
    },
    "analysis": {
        "summary": "brief summary of sentiment analysis",
        "notable_patterns": ["significant emotional patterns"],
        "emotional_themes": ["recurrent themes"],
        "clinical_relevance": "observations relevant to mental health",
        "limitations": ["limitations of this analysis"]
    }
}"""
        
        # Process with sentiment analysis model
        return self.process(text, "sentiment_analysis", opts)
    
    def analyze_wellness_dimensions(
        self, 
        text: str,
        dimensions: list[str] | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Analyze wellness dimensions in text.
        
        Args:
            text: Text to analyze
            dimensions: List of dimensions to analyze
            options: Additional processing options
            
        Returns:
            Wellness dimensions analysis results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI MentaLLaMA service is not initialized")
        
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
        
        # Create options for wellness dimensions analysis
        opts = options or {}
        opts["json_response"] = True
        
        # Add specific dimensions information if provided
        dimensions_instruction = ""
        if dimensions:
            dimension_list = ", ".join(dimensions)
            dimensions_instruction = f"Focus specifically on these wellness dimensions: {dimension_list}. "
        
        # Add instruction to get structured result
        opts["instruction"] = f"""Analyze the text across different dimensions of wellness. {dimensions_instruction}Provide your analysis in the following JSON format:
{{
    "wellness_dimensions": [
        {{
            "dimension": "emotional|social|physical|intellectual|occupational|environmental|spiritual|financial",
            "score": float between 0.0 (very poor) and 1.0 (excellent),
            "summary": "brief summary of findings",
            "strengths": ["positive aspects identified"],
            "challenges": ["areas of concern"],
            "evidence": ["excerpts from text"]
        }}
    ],
    "analysis": {{
        "overall_wellness_pattern": "brief overall assessment",
        "areas_of_strength": ["dimensions with highest wellness"],
        "areas_for_growth": ["dimensions with lowest wellness"],
        "balance_assessment": "assessment of balance across dimensions",
        "limitations": ["limitations of this analysis"]
    }},
    "recommendations": {{
        "clinical_focus_areas": ["suggested clinical priorities"],
        "suggested_resources": ["potentially helpful resources"],
        "assessment_tools": ["relevant formal assessments"]
    }}
}}"""
        
        # Process with wellness dimensions model
        return self.process(text, "wellness_dimensions", opts)
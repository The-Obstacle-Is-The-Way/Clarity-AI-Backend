"""
Unit tests for Mock MentaLLaMA implementation.

This module provides unit tests for the mock implementation of MentaLLaMA service.
"""

import json

import pytest

from app.core.exceptions import InvalidConfigurationError
from app.core.services.ml.providers.mock import MockMentaLLaMA


@pytest.fixture
def mock_service():
    """Create a mock MentaLLaMA service instance."""
    service = MockMentaLLaMA()
    service.initialize({"provider": "mock"})
    return service


@pytest.mark.db_required
def test_initialization_success():
    """Test successful initialization of mock service."""
    # Arrange
    service = MockMentaLLaMA()

    # Act
    service.initialize({"provider": "mock"})

    # Assert
    assert service.is_healthy() is True
    assert service._initialized is True
    assert len(service._available_models) > 0


def test_initialization_missing_provider():
    """Test initialization with missing provider."""
    # Arrange
    service = MockMentaLLaMA()

    # Act & Assert
    with pytest.raises(InvalidConfigurationError):
        service.initialize({})


def test_process(mock_service):
    """Test general processing functionality."""
    # Arrange
    prompt = "How are you feeling today?"

    # Act
    result = mock_service.process(prompt=prompt)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "response_id" in result
    assert "text" in result
    assert "model" in result
    assert "provider" in result
    assert "processing_time" in result
    assert "tokens_used" in result
    assert "created_at" in result
    assert "confidence" in result
    assert "metadata" in result
    assert result["provider"] == "mock"


def test_depression_detection_positive(mock_service):
    """Test depression detection with positive indicators."""
    # Arrange
    text = "I feel very depressed and hopeless. I don't enjoy anything anymore."

    # Act
    result = mock_service.depression_detection(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "depression_indicated" in result
    assert result["depression_indicated"] is True
    assert "key_indicators" in result
    assert len(result["key_indicators"]) > 0
    assert "severity" in result
    assert "rationale" in result


def test_depression_detection_negative(mock_service):
    """Test depression detection with negative indicators."""
    # Arrange
    text = "I'm feeling good today. Everything is going well."

    # Act
    result = mock_service.depression_detection(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "depression_indicated" in result
    assert result["depression_indicated"] is False
    assert "key_indicators" in result


def test_risk_assessment_high(mock_service):
    """Test risk assessment with high risk indicators."""
    # Arrange
    text = "I have a plan to end my life. I've decided I can't go on like this."

    # Act
    result = mock_service.risk_assessment(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "risk_level" in result
    assert result["risk_level"] == "high"
    assert "key_indicators" in result
    assert len(result["key_indicators"]) > 0
    assert "suggested_actions" in result
    assert len(result["suggested_actions"]) > 0
    assert "rationale" in result


def test_risk_assessment_low(mock_service):
    """Test risk assessment with low risk indicators."""
    # Arrange
    text = "I'm a bit stressed but overall doing fine. No thoughts of harming myself."

    # Act
    result = mock_service.risk_assessment(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "risk_level" in result
    assert result["risk_level"] == "low"
    assert "key_indicators" in result
    assert "suggested_actions" in result
    assert "rationale" in result


def test_sentiment_analysis_positive(mock_service):
    """Test sentiment analysis with positive sentiment."""
    # Arrange
    text = "I feel happy and excited about the progress I'm making. I'm grateful for all the support."

    # Act
    result = mock_service.sentiment_analysis(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "overall_sentiment" in result
    assert result["overall_sentiment"] == "positive"
    assert "sentiment_score" in result
    assert result["sentiment_score"] > 0
    assert "key_phrases" in result
    assert len(result["key_phrases"]) > 0
    assert "emotion_distribution" in result
    assert isinstance(result["emotion_distribution"], dict)


def test_sentiment_analysis_negative(mock_service):
    """Test sentiment analysis with negative sentiment."""
    # Arrange
    text = "I'm feeling unhappy and frustrated with everything. Nothing is working out."

    # Act
    result = mock_service.sentiment_analysis(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "overall_sentiment" in result
    assert result["overall_sentiment"] == "negative"
    assert "sentiment_score" in result
    assert result["sentiment_score"] < 0
    assert "key_phrases" in result
    assert "emotion_distribution" in result


def test_wellness_dimensions(mock_service):
    """Test wellness dimensions analysis."""
    # Arrange
    text = "I'm doing well at work but struggling with my personal relationships. I exercise regularly but feel spiritually disconnected."

    # Act
    result = mock_service.wellness_dimensions(text=text)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "dimension_scores" in result
    assert isinstance(result["dimension_scores"], dict)
    assert "areas_of_strength" in result
    assert isinstance(result["areas_of_strength"], list)
    assert "areas_for_improvement" in result
    assert isinstance(result["areas_for_improvement"], list)
    assert "recommendations" in result
    assert isinstance(result["recommendations"], list)


def test_service_shutdown(mock_service):
    """Test service shutdown functionality."""
    # Act
    mock_service.shutdown()

    # Assert
    assert mock_service._initialized is False
    assert mock_service._config is None
    assert mock_service._available_models == {}


def test_mock_response_parsing():
    """Test parsing of mock service responses."""
    # Arrange
    service = MockMentaLLaMA()
    service.initialize({"provider": "mock"})

    # Sample response from the mock service
    mock_response = json.dumps({
        "depression_indicated": True,
        "key_indicators": ["persistent sadness", "loss of interest"],
        "severity": "moderate",
        "rationale": "Test rationale",
        "confidence": 0.85,
    })

    # Act
    parsed = service._parse_depression_detection_result(mock_response)

    # Assert
    assert parsed is not None
    assert isinstance(parsed, dict)
    assert parsed["depression_indicated"] is True
    assert "key_indicators" in parsed
    assert len(parsed["key_indicators"]) == 2
    assert parsed["severity"] == "moderate"
    assert parsed["rationale"] == "Test rationale"
    assert parsed["confidence"] == 0.85


def test_generate_with_invalid_input(mock_service):
    """Test generation with invalid inputs."""
    # Act
    result = mock_service._generate(prompt="", model="invalid-model")

    # Assert
    assert result is not None
    assert "text" in result
    assert "processing_time" in result
    assert "tokens_used" in result
    assert "metadata" in result

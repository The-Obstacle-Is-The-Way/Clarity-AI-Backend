"""
Canonical implementation of the XGBoost service interface.

This module provides the definitive AWS-based implementation of the XGBoost service
that uses SageMaker for model hosting and prediction with comprehensive
HIPAA compliance and security considerations.
"""

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime
from typing import Any

import botocore.exceptions

from app.core.services.aws.interfaces import AWSServiceFactoryInterface
from app.core.services.ml.xgboost.exceptions import (
    ConfigurationError,
    DataPrivacyError,
    ModelNotFoundError,
    PredictionError,
    ResourceNotFoundError,
    ServiceConfigurationError,
    ServiceConnectionError,
    ValidationError,
)
from app.core.services.ml.xgboost.interface import (
    EventType,
    ModelType,
    Observer,
    PrivacyLevel,
    XGBoostInterface,
)
from app.domain.utils.datetime_utils import UTC, now_utc
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory
from app.presentation.api.schemas.xgboost import RiskLevel


class ServiceInitializationError(Exception):
    """Raised when service initialization fails."""
    
    def __init__(self, message: str, service: str = "", details: str = ""):
        super().__init__(message)
        self.service = service
        self.details = details


class AWSXGBoostService(XGBoostInterface):
    """
    AWS implementation of the XGBoost service interface using SageMaker.

    This is the canonical implementation that follows clean architecture principles
    and SOLID design patterns with comprehensive HIPAA compliance.
    """

    def __init__(self, aws_service_factory: AWSServiceFactoryInterface | None = None):
        """
        Initialize a new AWS XGBoost service.

        Args:
            aws_service_factory: Factory for AWS services (optional, will use default if None)
        """
        super().__init__()
        self._aws_factory = aws_service_factory or get_aws_service_factory()
        self._logger = logging.getLogger(__name__)

        # AWS services (initialized during setup)
        self._sagemaker_runtime = None
        self._sagemaker = None
        self._s3 = None
        self._dynamodb = None

        # Configuration
        self._region_name: str | None = None
        self._endpoint_prefix: str | None = None
        self._bucket_name: str | None = None
        self._dynamodb_table_name: str | None = None
        self._audit_table_name: str | None = None
        self._model_mappings: dict[str, str] = {}
        self._privacy_level = PrivacyLevel.STANDARD
        self._initialized = False

        # Observer pattern support
        self._observers: dict[EventType | str, set[Observer]] = {}

    @property
    def is_initialized(self) -> bool:
        """Check if the service is initialized."""
        return self._initialized

    async def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the AWS XGBoost service with configuration.

        Args:
            config: Configuration dictionary containing AWS settings

        Raises:
            ConfigurationError: If configuration is invalid
            ServiceConnectionError: If AWS services cannot be connected to
            ServiceConfigurationError: If AWS resources are not properly configured
        """
        try:
            # Configure logging
            log_level = config.get("log_level", "INFO")
            numeric_level = getattr(logging, log_level.upper(), None)
            if not isinstance(numeric_level, int):
                raise ConfigurationError(
                    f"Invalid log level: {log_level}",
                    field="log_level",
                    value=log_level,
                )

            self._logger.setLevel(numeric_level)

            # Extract and validate configuration
            self._validate_aws_config(config)

            # Set privacy level
            privacy_level = config.get("privacy_level", PrivacyLevel.STANDARD)
            if not isinstance(privacy_level, PrivacyLevel):
                try:
                    privacy_level = PrivacyLevel[privacy_level]
                except (KeyError, TypeError):
                    raise ConfigurationError(
                        f"Invalid privacy level: {privacy_level}",
                        field="privacy_level",
                        value=privacy_level,
                    )
            self._privacy_level = privacy_level

            # Initialize AWS services
            await self._initialize_aws_services()

            # Validate AWS resources
            try:
                await self._validate_aws_resources()
            except botocore.exceptions.ClientError as e:
                msg = e.response.get("Error", {}).get("Message", str(e))
                raise ServiceConfigurationError(
                    f"AWS configuration validation failed: {msg}",
                ) from e

            # Mark as initialized
            self._initialized = True

            # Notify observers
            await self._notify_observers(EventType.INITIALIZATION, {"status": "success"})
            self._logger.info("AWS XGBoost service initialized successfully")

        except Exception as e:
            self._logger.error(f"Failed to initialize AWS XGBoost service: {e!s}")
            if isinstance(e, (ConfigurationError, ServiceConfigurationError)):
                raise
            raise ConfigurationError(f"Failed to initialize AWS XGBoost service: {e!s}") from e

    async def predict(
        self, patient_id: str, features: dict[str, Any], model_type: str, **kwargs
    ) -> dict[str, Any]:
        """
        Generic prediction method required by MLServiceInterface.

        Args:
            patient_id: ID of the patient
            features: Dictionary of features for prediction
            model_type: Type of model to use for prediction
            **kwargs: Additional arguments for prediction

        Returns:
            Dictionary with prediction results

        Raises:
            ValidationError: If parameters are invalid
            ModelNotFoundError: If model type is not supported
            PredictionError: If prediction fails
        """
        await self._ensure_initialized()

        # Route to appropriate specialized prediction method based on model_type
        if model_type.lower() == "risk":
            risk_type = kwargs.get("risk_type", "general")
            time_frame_days = kwargs.get("time_frame_days", 30)

            return await self.predict_risk(
                patient_id=patient_id,
                risk_type=risk_type,
                clinical_data=features,
                time_frame_days=time_frame_days,
            )

        elif model_type.lower() == "treatment_response":
            treatment_type = kwargs.get("treatment_type", "medication")
            treatment_details = kwargs.get("treatment_details", {})

            return await self.predict_treatment_response(
                patient_id=patient_id,
                treatment_type=treatment_type,
                treatment_details=treatment_details,
                clinical_data=features,
            )

        elif model_type.lower() == "outcome":
            outcome_timeframe = kwargs.get("outcome_timeframe", {"timeframe": "short_term"})
            treatment_plan = kwargs.get("treatment_plan", {})
            social_determinants = kwargs.get("social_determinants")
            comorbidities = kwargs.get("comorbidities")

            return await self.predict_outcome(
                patient_id=patient_id,
                outcome_timeframe=outcome_timeframe,
                clinical_data=features,
                treatment_plan=treatment_plan,
                social_determinants=social_determinants,
                comorbidities=comorbidities,
            )

        else:
            raise ModelNotFoundError(
                f"Prediction for model type '{model_type}' is not implemented"
            )

    async def predict_risk(
        self, patient_id: str, risk_type: str, clinical_data: dict[str, Any], **kwargs
    ) -> dict[str, Any]:
        """
        Predict risk level using a risk model.

        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict (e.g., 'risk-suicide')
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters

        Returns:
            Risk prediction result with risk score, level, and metadata

        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
            ServiceConnectionError: If AWS services cannot be connected to
        """
        await self._ensure_initialized()

        # Validate parameters
        self._validate_risk_prediction_params(patient_id, risk_type, clinical_data)

        # Check if risk type is supported
        endpoint_name = self._get_endpoint_for_risk_type(risk_type)
        if not endpoint_name:
            available_models = list(self._model_mappings.keys())
            raise ValidationError(
                f"Unsupported risk type: {risk_type}. Available types: {available_models}",
                field="risk_type",
                value=risk_type,
            )

        # Generate prediction ID and timestamp
        prediction_id = f"pred-{uuid.uuid4()}"
        timestamp = now_utc()

        try:
            # Extract features for model
            features = await self._extract_features_for_model(clinical_data)

            # Prepare request payload
            payload = {
                "features": features["features"],
                "patient_id": patient_id,
                "timestamp": timestamp.isoformat(),
                **kwargs
            }

            # Validate for PHI
            await self._validate_no_phi(payload)

            # Make prediction request
            prediction_result = await self._invoke_sagemaker_endpoint(endpoint_name, payload)

            # Process prediction result
            result = await self._process_risk_prediction_result(
                prediction_result, prediction_id, patient_id, risk_type, timestamp
            )

            # Store prediction for audit and tracking
            await self._store_prediction(
                prediction_id=prediction_id,
                patient_id=patient_id,
                model_type=risk_type,
                input_data=clinical_data,
                output_data=result,
            )

            # Notify observers
            await self._notify_observers(
                EventType.PREDICTION,
                {
                    "prediction_id": prediction_id,
                    "patient_id": patient_id,
                    "model_type": risk_type,
                    "status": "success",
                },
            )

            return result

        except (
            ValidationError,
            DataPrivacyError,
            ResourceNotFoundError,
            ModelNotFoundError,
            PredictionError,
            ServiceConnectionError,
        ) as e:
            # Expected exceptions, log and re-raise
            self._logger.warning(
                f"Prediction error for patient {patient_id}, risk type {risk_type}: {e!s}"
            )
            await self._notify_observers(
                EventType.ERROR,
                {
                    "patient_id": patient_id,
                    "model_type": risk_type,
                    "error": str(e),
                    "error_type": e.__class__.__name__,
                },
            )
            raise

        except Exception as e:
            # Unexpected exception, log and wrap
            self._logger.error(
                f"Unexpected error in predict_risk for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            await self._notify_observers(
                EventType.ERROR,
                {
                    "patient_id": patient_id,
                    "model_type": risk_type,
                    "error": str(e),
                    "error_type": "UnexpectedError",
                },
            )
            raise PredictionError(f"Unexpected error in prediction: {e!s}") from e

    async def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
        **kwargs,
    ) -> dict[str, Any]:
        """
        Predict response to a psychiatric treatment.

        Args:
            patient_id: Patient identifier
            treatment_type: Type of treatment (e.g., medication_ssri)
            treatment_details: Treatment details
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters

        Returns:
            Treatment response prediction result

        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        await self._ensure_initialized()

        # Validate inputs
        self._validate_treatment_prediction_params(
            patient_id, treatment_type, treatment_details, clinical_data
        )

        # Map treatment type to endpoint
        endpoint_name = self._get_endpoint_for_treatment_type(treatment_type)
        if not endpoint_name:
            raise ModelNotFoundError(f"No model found for treatment type: {treatment_type}")

        # Generate prediction ID
        prediction_id = f"pred-{uuid.uuid4()}"
        timestamp = now_utc()

        # Prepare payload
        payload = {
            "patient_id": patient_id,
            "treatment_type": treatment_type,
            "treatment_details": treatment_details,
            "clinical_data": clinical_data,
            "timestamp": timestamp.isoformat(),
            **kwargs,
        }

        # Validate for PHI
        await self._validate_no_phi(payload)

        # Invoke endpoint
        prediction_result = await self._invoke_sagemaker_endpoint(endpoint_name, payload)

        # Process result
        result = await self._process_treatment_prediction_result(
            prediction_result, prediction_id, patient_id, treatment_type, timestamp
        )

        # Store prediction
        await self._store_prediction(
            prediction_id=prediction_id,
            patient_id=patient_id,
            model_type=treatment_type,
            input_data=payload,
            output_data=result,
        )

        # Add audit log
        await self._add_audit_log(
            action="predict_treatment_response",
            patient_id=patient_id,
            model_type=treatment_type,
            prediction_id=prediction_id,
        )

        return result

    async def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: dict[str, Any],
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
        **kwargs,
    ) -> dict[str, Any]:
        """
        Predict clinical outcomes based on treatment plan.

        Args:
            patient_id: Patient identifier
            outcome_timeframe: Timeframe for outcome prediction
            clinical_data: Clinical data for prediction
            treatment_plan: Treatment plan details
            **kwargs: Additional prediction parameters

        Returns:
            Outcome prediction result

        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        await self._ensure_initialized()

        # Validate inputs
        self._validate_outcome_prediction_params(
            patient_id, outcome_timeframe, clinical_data, treatment_plan
        )

        # Determine outcome type from treatment plan
        outcome_type = kwargs.get("outcome_type", "symptom")
        if outcome_type not in ["symptom", "functional", "quality_of_life"]:
            raise ValidationError(
                f"Invalid outcome type: {outcome_type}. Must be one of: symptom, functional, quality_of_life"
            )

        # Map outcome type to endpoint
        endpoint_name = self._get_endpoint_for_outcome_type(outcome_type)
        if not endpoint_name:
            raise ModelNotFoundError(f"No model found for outcome type: {outcome_type}")

        # Generate prediction ID
        prediction_id = f"pred-{uuid.uuid4()}"
        timestamp = now_utc()

        # Prepare payload
        payload = {
            "patient_id": patient_id,
            "outcome_timeframe": outcome_timeframe,
            "clinical_data": clinical_data,
            "treatment_plan": treatment_plan,
            "timestamp": timestamp.isoformat(),
            **kwargs,
        }

        # Validate for PHI
        await self._validate_no_phi(payload)

        # Invoke endpoint
        prediction_result = await self._invoke_sagemaker_endpoint(endpoint_name, payload)

        # Process result
        result = await self._process_outcome_prediction_result(
            prediction_result, prediction_id, patient_id, outcome_type, timestamp
        )

        # Store prediction
        await self._store_prediction(
            prediction_id=prediction_id,
            patient_id=patient_id,
            model_type=f"{outcome_type}-outcome",
            input_data=payload,
            output_data=result,
        )

        # Add audit log
        await self._add_audit_log(
            action="predict_outcome",
            patient_id=patient_id,
            model_type=f"{outcome_type}-outcome",
            prediction_id=prediction_id,
        )

        return result

    async def get_available_models(self) -> list[dict[str, Any]]:
        """
        Get a list of available models.

        Returns:
            List of available models with basic info
        """
        await self._ensure_initialized()

        try:
            # Get SageMaker endpoints
            sagemaker = self._aws_factory.get_sagemaker_service()
            if sagemaker is None:
                raise ServiceConnectionError("Failed to get SageMaker service")

            response = await sagemaker.list_endpoints()

            # Filter for XGBoost endpoints
            available_models = []
            prefix = self._endpoint_prefix or ""

            for endpoint in response.get("Endpoints", []):
                endpoint_name = endpoint.get("EndpointName", "")
                if prefix and endpoint_name.startswith(prefix):
                    model_type = self._get_model_type_from_endpoint(endpoint_name)
                    
                    available_models.append(
                        {
                            "model_type": model_type,
                            "endpoint_name": endpoint_name,
                            "status": endpoint.get("EndpointStatus", "Unknown"),
                            "creation_time": endpoint.get("CreationTime", "Unknown"),
                        }
                    )

            return available_models

        except Exception as e:
            self._logger.error(f"Failed to get available models: {e!s}")
            return []

    async def get_feature_importance(
        self, patient_id: str, model_type: str, prediction_id: str
    ) -> dict[str, Any]:
        """
        Get feature importance for a prediction.

        Args:
            patient_id: Patient identifier
            model_type: Type of model
            prediction_id: Prediction identifier

        Returns:
            Feature importance data

        Raises:
            ResourceNotFoundError: If prediction not found
            ValidationError: If parameters are invalid
        """
        await self._ensure_initialized()

        # Validate inputs
        if not all([patient_id, model_type, prediction_id]):
            raise ValidationError("Patient ID, model type, and prediction ID are all required")

        # Get prediction from DynamoDB
        dynamodb = self._aws_factory.get_dynamodb_service()
        if dynamodb is None:
            raise ServiceConnectionError("Failed to get DynamoDB service")

        response = await dynamodb.get_item(
            table_name=self._dynamodb_table_name,
            key={"prediction_id": prediction_id, "patient_id": patient_id},
        )

        if "Item" not in response:
            raise ResourceNotFoundError(f"Prediction not found for ID: {prediction_id}")

        prediction = response["Item"]

        # Try to get feature importance from explanation endpoint
        try:
            endpoint_name = f"{self._get_endpoint_for_model_type(model_type)}-explain"
            input_data = prediction.get("input_data", {})
            payload = {"prediction_id": prediction_id, "input_data": input_data}

            feature_importance = await self._invoke_sagemaker_endpoint(endpoint_name, payload)
            return feature_importance

        except Exception as e:
            self._logger.warning(f"Failed to get feature importance from endpoint: {e!s}")
            # Fallback to synthetic feature importance
            return self._generate_synthetic_feature_importance(prediction)

    async def get_model_info(self, model_type: str) -> dict[str, Any]:
        """
        Get information about a model.

        Args:
            model_type: Type of model

        Returns:
            Model information

        Raises:
            ResourceNotFoundError: If model not found
            ValidationError: If parameters are invalid
        """
        await self._ensure_initialized()

        if not model_type:
            raise ValidationError("Model type must be specified")

        try:
            # Map model type to endpoint name
            endpoint_name = self._get_endpoint_for_model_type(model_type)
            if not endpoint_name:
                raise ModelNotFoundError(f"Unknown model type: {model_type}")

            # Get endpoint details
            sagemaker = self._aws_factory.get_sagemaker_service()
            if sagemaker is None:
                raise ServiceConnectionError("Failed to get SageMaker service")

            response = await sagemaker.describe_endpoint(endpoint_name=endpoint_name)

            # Format model information
            model_info = {
                "model_type": model_type,
                "endpoint_name": endpoint_name,
                "status": response.get("EndpointStatus", "Unknown"),
                "created_at": response.get("CreationTime", "Unknown"),
                "last_modified": response.get("LastModifiedTime", "Unknown"),
                "arn": response.get("EndpointArn", "Unknown"),
                "config": {
                    "instance_type": "ml.m5.large",
                    "model_framework": "xgboost",
                    "model_version": "1.0",
                },
            }

            return model_info

        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["ValidationException", "ResourceNotFound"]:
                raise ModelNotFoundError(f"Model not found: {model_type}")
            raise ServiceConnectionError(f"Failed to get model info: {e!s}")

        except Exception as e:
            self._logger.error(f"Failed to get model info: {e!s}")
            raise ServiceConnectionError(f"Failed to get model info: {e!s}")

    async def healthcheck(self) -> dict[str, Any]:
        """
        Perform a health check of the XGBoost service.

        Returns:
            Health check results with status (HEALTHY, DEGRADED, UNHEALTHY)
        """
        await self._ensure_initialized()

        try:
            health_status = {
                "status": "HEALTHY",
                "components": {
                    "sagemaker": "HEALTHY",
                    "s3": "HEALTHY",
                    "dynamodb": "HEALTHY",
                },
                "details": {"endpoints": []},
            }

            # Check S3 bucket
            try:
                s3 = self._aws_factory.get_s3_service()
                if s3 is None:
                    raise ServiceConnectionError("Failed to get S3 service")
                
                bucket_exists = await s3.check_bucket_exists(self._bucket_name)
                health_status["components"]["s3"] = "HEALTHY" if bucket_exists else "UNHEALTHY"
                if not bucket_exists:
                    health_status["status"] = "DEGRADED"
            except Exception as e:
                health_status["components"]["s3"] = "UNHEALTHY"
                health_status["status"] = "DEGRADED"
                self._logger.error(f"S3 health check failed: {e}")

            # Check DynamoDB table
            try:
                dynamodb = self._aws_factory.get_dynamodb_service()
                if dynamodb is None:
                    raise ServiceConnectionError("Failed to get DynamoDB service")
                
                await dynamodb.scan_table(self._dynamodb_table_name)
                health_status["components"]["dynamodb"] = "HEALTHY"
            except Exception as e:
                health_status["components"]["dynamodb"] = "UNHEALTHY"
                health_status["status"] = "DEGRADED"
                self._logger.error(f"DynamoDB health check failed: {e}")

            # Check SageMaker endpoints
            try:
                sagemaker = self._aws_factory.get_sagemaker_service()
                if sagemaker is None:
                    raise ServiceConnectionError("Failed to get SageMaker service")
                
                endpoints_response = await sagemaker.list_endpoints()
                endpoints = endpoints_response.get("Endpoints", [])

                prefix = self._endpoint_prefix or ""
                endpoints_list = []
                endpoint_statuses = []

                for endpoint in endpoints:
                    endpoint_name = endpoint.get("EndpointName", "")
                    if prefix and endpoint_name.startswith(prefix):
                        status = endpoint.get("EndpointStatus", "Unknown")
                        endpoints_list.append({"name": endpoint_name, "status": status})
                        endpoint_statuses.append(status)

                health_status["details"]["endpoints"] = endpoints_list

                # If no endpoints are in service, consider degraded
                if "InService" not in endpoint_statuses and endpoints_list:
                    health_status["components"]["sagemaker"] = "DEGRADED"
                    health_status["status"] = "DEGRADED"
            except Exception as e:
                health_status["components"]["sagemaker"] = "UNHEALTHY"
                health_status["status"] = "DEGRADED"
                self._logger.error(f"SageMaker health check failed: {e}")

            return health_status

        except Exception as e:
            self._logger.error(f"Health check failed: {e}")
            return {
                "status": "UNHEALTHY",
                "components": {
                    "sagemaker": "UNKNOWN",
                    "s3": "UNKNOWN",
                    "dynamodb": "UNKNOWN",
                },
                "error": str(e),
            }

    async def register_observer(self, event_type: EventType | str, observer: Observer) -> None:
        """
        Register an observer for a specific event type.

        Args:
            event_type: Type of event to observe, or "*" for all events
            observer: Observer to register
        """
        if event_type not in self._observers:
            self._observers[event_type] = set()

        self._observers[event_type].add(observer)
        self._logger.debug(f"Observer {observer} registered for event type {event_type}")

    async def unregister_observer(self, event_type: EventType | str, observer: Observer) -> None:
        """
        Unregister an observer for a specific event type.

        Args:
            event_type: Type of event to stop observing
            observer: Observer to unregister
        """
        if event_type in self._observers and observer in self._observers[event_type]:
            self._observers[event_type].remove(observer)
            self._logger.debug(f"Observer {observer} unregistered for event type {event_type}")

    # Private helper methods

    def _validate_aws_config(self, config: dict[str, Any]) -> None:
        """Validate the AWS configuration."""
        self._region_name = config.get("aws_region") or os.environ.get("AWS_REGION", "us-east-1")
        self._endpoint_prefix = config.get("endpoint_prefix") or os.environ.get("SAGEMAKER_ENDPOINT_PREFIX", "xgboost-")
        self._bucket_name = config.get("bucket_name") or os.environ.get("XGBOOST_S3_BUCKET", "novamind-xgboost-data")
        self._dynamodb_table_name = config.get("dynamodb_table_name") or os.environ.get("XGBOOST_DYNAMODB_TABLE", "xgboost-predictions")
        self._audit_table_name = config.get("audit_table_name") or os.environ.get("XGBOOST_AUDIT_TABLE", "xgboost-audit-log")

        model_mappings = config.get("model_mappings", {})
        if not isinstance(model_mappings, dict):
            raise ConfigurationError(
                f"Invalid model_mappings type: {type(model_mappings)}",
                field="model_mappings",
                value=model_mappings,
            )
        self._model_mappings = model_mappings

    async def _initialize_aws_services(self) -> None:
        """Initialize AWS service clients."""
        try:
            self._sagemaker = self._aws_factory.get_sagemaker_service()
            self._sagemaker_runtime = self._aws_factory.get_sagemaker_runtime()
            self._s3 = self._aws_factory.get_s3_service()
            self._dynamodb = self._aws_factory.get_dynamodb_service()
        except Exception as e:
            self._logger.error(f"Failed to initialize AWS clients: {e}")
            raise ServiceConnectionError(
                f"Failed to initialize AWS clients: {e!s}",
                service="AWS",
                error_type="ClientInitialization",
                details=str(e),
            ) from e

    async def _validate_aws_resources(self) -> None:
        """Validate that required AWS resources exist and are accessible."""
        if self._s3 is None:
            raise ServiceConnectionError("S3 service not initialized")
        
        if not await self._s3.check_bucket_exists(self._bucket_name):
            raise ServiceConnectionError(
                f"S3 bucket {self._bucket_name} does not exist or is not accessible",
                service="S3",
                details=f"Bucket: {self._bucket_name}",
            )

        if self._sagemaker is None:
            raise ServiceConnectionError("SageMaker service not initialized")
        
        endpoints = await self._sagemaker.list_endpoints()
        self._logger.info(f"Found {len(endpoints.get('Endpoints', []))} SageMaker endpoints")

    async def _ensure_initialized(self) -> None:
        """Ensure the service is initialized before using it."""
        if not self._initialized:
            # Auto-initialize with default configuration
            await self.initialize({
                "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
                "endpoint_prefix": os.environ.get("SAGEMAKER_ENDPOINT_PREFIX", "xgboost-"),
                "bucket_name": os.environ.get("XGBOOST_S3_BUCKET", "novamind-xgboost-data"),
                "dynamodb_table_name": os.environ.get("XGBOOST_DYNAMODB_TABLE", "xgboost-predictions"),
                "audit_table_name": os.environ.get("XGBOOST_AUDIT_TABLE", "xgboost-audit-log"),
                "model_mappings": {
                    ModelType.RISK_SUICIDE.value: "suicide-risk",
                    ModelType.RISK_HOSPITALIZATION.value: "readmission-risk",
                    ModelType.TREATMENT_MEDICATION_SSRI.value: "medication-ssri-response",
                    ModelType.TREATMENT_MEDICATION_SNRI.value: "medication-snri-response",
                    ModelType.TREATMENT_THERAPY_CBT.value: "therapy-cbt-response",
                },
            })

    def _validate_risk_prediction_params(
        self, patient_id: str, risk_type: str, clinical_data: dict[str, Any]
    ) -> None:
        """Validate risk prediction parameters."""
        if not patient_id or not isinstance(patient_id, str):
            raise ValidationError(
                "Patient ID must be a non-empty string",
                field="patient_id",
                value=patient_id,
            )

        if not clinical_data or not isinstance(clinical_data, dict):
            raise ValidationError(
                "Clinical data must be a non-empty dictionary",
                field="clinical_data",
                value=clinical_data,
            )

        if not risk_type or not isinstance(risk_type, str):
            raise ValidationError(
                "Risk type must be a non-empty string",
                field="risk_type",
                value=risk_type,
            )

    def _validate_treatment_prediction_params(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
    ) -> None:
        """Validate treatment prediction parameters."""
        if not patient_id:
            raise ValidationError("Patient ID is required", field="patient_id")

        if not treatment_type:
            raise ValidationError("Treatment type is required", field="treatment_type")

        if not treatment_details:
            raise ValidationError("Treatment details are required", field="treatment_details")

        if not clinical_data:
            raise ValidationError("Clinical data is required", field="clinical_data")

    def _validate_outcome_prediction_params(
        self,
        patient_id: str,
        outcome_timeframe: dict[str, Any],
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
    ) -> None:
        """Validate outcome prediction parameters."""
        if not patient_id:
            raise ValidationError("Patient ID is required", field="patient_id")

        if not outcome_timeframe:
            raise ValidationError("Outcome timeframe is required", field="outcome_timeframe")

        if not clinical_data:
            raise ValidationError("Clinical data is required", field="clinical_data")

        if not treatment_plan:
            raise ValidationError("Treatment plan is required", field="treatment_plan")

    async def _validate_no_phi(self, data: dict[str, Any]) -> None:
        """Validate that data contains no PHI."""
        data_str = json.dumps(data)

        # Define PHI patterns
        ssn_pattern = r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"
        mrn_pattern = r"\b(MRN|mrn)[-:]?\s*\d+\b"
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        phone_pattern = r"\b(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"

        # Check for PHI based on privacy level
        if self._privacy_level in [PrivacyLevel.STANDARD, PrivacyLevel.ENHANCED]:
            if re.search(ssn_pattern, data_str) or re.search(mrn_pattern, data_str):
                raise DataPrivacyError(
                    "Protected health information (SSN/MRN) detected in data",
                    details="SSN or MRN pattern detected",
                )

        if self._privacy_level in [PrivacyLevel.ENHANCED, PrivacyLevel.MAXIMUM]:
            if re.search(email_pattern, data_str) or re.search(phone_pattern, data_str):
                raise DataPrivacyError(
                    "Protected health information (contact details) detected in data",
                    details="Email or phone number detected",
                )

    def _get_endpoint_for_risk_type(self, risk_type: str) -> str | None:
        """Get the SageMaker endpoint name for a risk type."""
        if risk_type in self._model_mappings:
            return f"{self._endpoint_prefix}{self._model_mappings[risk_type]}"
        return None

    def _get_endpoint_for_treatment_type(self, treatment_type: str) -> str | None:
        """Get the SageMaker endpoint name for a treatment type."""
        if treatment_type in self._model_mappings:
            return f"{self._endpoint_prefix}{self._model_mappings[treatment_type]}"
        return None

    def _get_endpoint_for_outcome_type(self, outcome_type: str) -> str | None:
        """Get the SageMaker endpoint name for an outcome type."""
        model_key = f"{outcome_type}-outcome"
        if model_key in self._model_mappings:
            return f"{self._endpoint_prefix}{self._model_mappings[model_key]}"
        return None

    def _get_endpoint_for_model_type(self, model_type: str) -> str | None:
        """Get the SageMaker endpoint name for a model type."""
        if model_type in self._model_mappings:
            return f"{self._endpoint_prefix}{self._model_mappings[model_type]}"
        return None

    def _get_model_type_from_endpoint(self, endpoint_name: str) -> str:
        """Extract model type from endpoint name."""
        prefix = self._endpoint_prefix or ""
        if endpoint_name.startswith(prefix):
            suffix = endpoint_name[len(prefix):]
            # Reverse lookup in model mappings
            for model_type, endpoint_suffix in self._model_mappings.items():
                if suffix == endpoint_suffix:
                    return model_type
            return suffix
        return endpoint_name

    async def _extract_features_for_model(
        self, clinical_data: dict[str, Any]
    ) -> dict[str, list[float]]:
        """Extract features from clinical data for model input."""
        if "features" in clinical_data and isinstance(clinical_data["features"], list):
            return {"features": clinical_data["features"]}

        # Simplified feature extraction logic
        features = []

        # Extract assessment scores if available
        if "assessment_scores" in clinical_data:
            scores = clinical_data["assessment_scores"]
            if isinstance(scores, dict):
                for score_name, value in scores.items():
                    if isinstance(value, (int, float)):
                        features.append(float(value))

        # If no features were extracted, use a default feature vector
        if not features:
            features = [0.5, 0.5, 0.5]  # Default feature vector

        return {"features": features}

    async def _invoke_sagemaker_endpoint(
        self, endpoint_name: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Invoke a SageMaker endpoint with the given payload."""
        try:
            payload_bytes = json.dumps(payload).encode("utf-8")

            if self._sagemaker_runtime is None:
                raise ServiceConnectionError("SageMaker runtime client not initialized")

            self._logger.debug(f"Invoking endpoint {endpoint_name} with payload: {payload}")
            response = await self._sagemaker_runtime.invoke_endpoint(
                EndpointName=endpoint_name,
                ContentType="application/json",
                Body=payload_bytes,
            )

            if response is None or "Body" not in response:
                raise PredictionError(f"Invalid response from SageMaker: {response}")

            response_body = await response["Body"].read()
            self._logger.debug(f"Received response: {response_body}")
            return json.loads(response_body.decode("utf-8"))

        except Exception as e:
            if "Connection refused" in str(e) or "timeout" in str(e).lower():
                raise ServiceConnectionError(
                    f"Failed to connect to SageMaker endpoint: {endpoint_name}"
                ) from e
            else:
                raise PredictionError(f"Failed to get prediction from SageMaker: {e!s}") from e

    async def _process_risk_prediction_result(
        self,
        prediction_result: dict[str, Any],
        prediction_id: str,
        patient_id: str,
        risk_type: str,
        timestamp: datetime,
    ) -> dict[str, Any]:
        """Process risk prediction result."""
        if not isinstance(prediction_result, dict) or "prediction" not in prediction_result:
            raise PredictionError(
                "Invalid prediction result format from SageMaker",
                details=prediction_result,
            )

        prediction = prediction_result.get("prediction", {})
        risk_score = prediction.get("score")
        risk_level_str = prediction.get("risk_level", "").upper()

        # Map string risk level to enum
        try:
            risk_level = RiskLevel[risk_level_str]
        except (KeyError, ValueError):
            # Default to mapping based on score if level string is invalid
            if risk_score is not None:
                if risk_score >= 0.7:
                    risk_level = RiskLevel.HIGH
                elif risk_score >= 0.3:
                    risk_level = RiskLevel.MEDIUM
                else:
                    risk_level = RiskLevel.LOW
            else:
                risk_level = RiskLevel.UNKNOWN

        return {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "risk_type": risk_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "timestamp": timestamp.isoformat(),
            "confidence": prediction.get("confidence"),
            "factors": prediction.get("contributing_factors", []),
        }

    async def _process_treatment_prediction_result(
        self,
        prediction_result: dict[str, Any],
        prediction_id: str,
        patient_id: str,
        treatment_type: str,
        timestamp: datetime,
    ) -> dict[str, Any]:
        """Process treatment prediction result."""
        response_probability = prediction_result.get("response_probability", 0)

        return {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "treatment_type": treatment_type,
            "response_probability": response_probability,
            "confidence": prediction_result.get("confidence", 0),
            "factors": prediction_result.get("contributing_factors", []),
            "expected_onset_days": prediction_result.get("expected_onset_days"),
            "expected_duration_weeks": prediction_result.get("expected_duration_weeks"),
            "side_effects": prediction_result.get("side_effects", []),
            "timestamp": timestamp.isoformat(),
        }

    async def _process_outcome_prediction_result(
        self,
        prediction_result: dict[str, Any],
        prediction_id: str,
        patient_id: str,
        outcome_type: str,
        timestamp: datetime,
    ) -> dict[str, Any]:
        """Process outcome prediction result."""
        return {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "outcome_type": outcome_type,
            "outcome_probability": prediction_result.get("outcome_probability", 0),
            "confidence": prediction_result.get("confidence", 0),
            "factors": prediction_result.get("contributing_factors", []),
            "expected_timeframe": prediction_result.get("expected_timeframe"),
            "timestamp": timestamp.isoformat(),
        }

    async def _store_prediction(
        self,
        prediction_id: str,
        patient_id: str,
        model_type: str,
        input_data: dict[str, Any],
        output_data: dict[str, Any],
    ) -> None:
        """Store prediction data for audit and tracking purposes."""
        if self._dynamodb is None:
            self._logger.warning("DynamoDB service not available, skipping prediction storage")
            return

        item = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "model_type": model_type,
            "timestamp": now_utc().isoformat(),
            "input_data": json.dumps(input_data),
            "output_data": json.dumps(output_data),
            "ttl": int(time.time()) + (90 * 24 * 60 * 60),  # 90 days TTL for HIPAA compliance
        }

        try:
            await self._dynamodb.put_item(self._dynamodb_table_name, item)
            self._logger.info(f"Stored prediction {prediction_id} for patient {patient_id}")
        except Exception as e:
            self._logger.error(f"Failed to store prediction: {e}")

    async def _add_audit_log(
        self,
        action: str,
        patient_id: str,
        model_type: str,
        prediction_id: str,
        **kwargs,
    ) -> None:
        """Add audit log entry for HIPAA compliance."""
        if self._dynamodb is None:
            self._logger.warning("DynamoDB service not available, skipping audit log")
            return

        audit_item = {
            "audit_id": str(uuid.uuid4()),
            "timestamp": now_utc().isoformat(),
            "action": action,
            "resource_type": "PREDICTION",
            "resource_id": prediction_id,
            "patient_id": patient_id,
            "details": json.dumps({"model_type": model_type, **kwargs}),
        }

        try:
            await self._dynamodb.put_item(self._audit_table_name, audit_item)
        except Exception as e:
            # Audit logging should not prevent operation from succeeding
            self._logger.error(f"Failed to write audit log: {e}")

    async def _notify_observers(self, event_type: EventType, data: dict[str, Any]) -> None:
        """Notify all observers registered for a specific event type."""
        # Specific event observers
        if event_type in self._observers:
            for observer in self._observers[event_type]:
                try:
                    await observer.on_event(event_type, data)
                except Exception as e:
                    self._logger.error(
                        f"Error notifying observer {observer} for event {event_type}: {e}"
                    )

        # Wildcard observers (listening to all events)
        if "*" in self._observers:
            for observer in self._observers["*"]:
                try:
                    await observer.on_event(event_type, data)
                except Exception as e:
                    self._logger.error(
                        f"Error notifying wildcard observer {observer} for event {event_type}: {e}"
                    )

    def _generate_synthetic_feature_importance(self, prediction: dict[str, Any]) -> dict[str, Any]:
        """Generate synthetic feature importance when no explanation endpoint is available."""
        input_data = prediction.get("input_data", {}).get("clinical_data", {})
        features = list(input_data.keys())

        # Generate random importance scores that sum to 1.0
        import random

        scores = [random.random() for _ in features]
        total = sum(scores)
        normalized_scores = [score / total for score in scores] if total > 0 else scores

        # Sort features by importance
        feature_importance = sorted(
            zip(features, normalized_scores, strict=False),
            key=lambda x: x[1],
            reverse=True,
        )

        return {
            "prediction_id": prediction.get("prediction_id"),
            "feature_importance": [
                {"feature": feature, "importance": importance}
                for feature, importance in feature_importance
            ],
            "is_synthetic": True,
            "model_type": prediction.get("model_type"),
            "timestamp": datetime.now(UTC).isoformat(),
        }

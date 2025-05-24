"""AWS XGBoost service implementation.

This module provides AWS-based XGBoost ML services using SageMaker, S3, and DynamoDB.
Follows clean architecture principles with proper dependency injection and SOLID design.
"""

import json
import logging
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError

from app.core.interfaces.services.ml.xgboost import AWSServiceFactoryInterface, XGBoostInterface
from app.core.services.ml.xgboost.events import EventType, Observable, Observer
from app.core.services.ml.xgboost.exceptions import (
    ConfigurationError,
    ModelInvocationError,
    ModelNotFoundError,
    ModelTimeoutError,
    PredictionError,
    ResourceNotFoundError,
    SerializationError,
    ServiceConfigurationError,
    ServiceConnectionError,
    ThrottlingError,
    ValidationError,
)

logger = logging.getLogger(__name__)


class AWSServiceFactory(AWSServiceFactoryInterface):
    """Factory for creating AWS service clients with proper configuration."""

    def __init__(self, region_name: str = "us-east-1", **kwargs: Any) -> None:
        """Initialize AWS service factory.

        Args:
            region_name: AWS region name
            **kwargs: Additional AWS configuration
        """
        self.region_name = region_name
        self.config = kwargs

    def create_sagemaker_runtime(self) -> Any:
        """Create SageMaker runtime client."""
        try:
            return boto3.client("sagemaker-runtime", region_name=self.region_name, **self.config)
        except Exception as e:
            raise ServiceConfigurationError(
                f"Failed to create SageMaker runtime client: {e!s}",
                service_name="sagemaker-runtime",
            ) from e

    def create_sagemaker(self) -> Any:
        """Create SageMaker client."""
        try:
            return boto3.client("sagemaker", region_name=self.region_name, **self.config)
        except Exception as e:
            raise ServiceConfigurationError(
                f"Failed to create SageMaker client: {e!s}",
                service_name="sagemaker",
            ) from e

    def create_s3(self) -> Any:
        """Create S3 client."""
        try:
            return boto3.client("s3", region_name=self.region_name, **self.config)
        except Exception as e:
            raise ServiceConfigurationError(
                f"Failed to create S3 client: {e!s}",
                service_name="s3",
            ) from e

    def create_dynamodb(self) -> Any:
        """Create DynamoDB client."""
        try:
            return boto3.client("dynamodb", region_name=self.region_name, **self.config)
        except Exception as e:
            raise ServiceConfigurationError(
                f"Failed to create DynamoDB client: {e!s}",
                service_name="dynamodb",
            ) from e


class AWSXGBoostService(XGBoostInterface, Observable):
    """AWS-based XGBoost service implementation using SageMaker.

    This service provides XGBoost ML capabilities through AWS SageMaker endpoints,
    with S3 for model storage and DynamoDB for metadata management.
    """

    def __init__(self, aws_factory: AWSServiceFactoryInterface) -> None:
        """Initialize AWS XGBoost service.

        Args:
            aws_factory: Factory for creating AWS service clients
        """
        self._aws_factory = aws_factory
        self._sagemaker_runtime: Any | None = None
        self._sagemaker: Any | None = None
        self._s3: Any | None = None
        self._dynamodb: Any | None = None
        self._initialized = False
        self._config: dict[str, Any] = {}
        self._observers: dict[EventType, list[Observer]] = {}

        # Initialize observer registry
        for event_type in EventType:
            self._observers[event_type] = []

    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the XGBoost service with configuration.

        Args:
            config: Configuration dictionary containing AWS settings

        Raises:
            ConfigurationError: If configuration is invalid
            ServiceConfigurationError: If AWS services cannot be initialized
        """
        try:
            self._validate_config(config)
            self._config = config.copy()

            # Initialize AWS clients
            self._sagemaker_runtime = self._aws_factory.create_sagemaker_runtime()
            self._sagemaker = self._aws_factory.create_sagemaker()
            self._s3 = self._aws_factory.create_s3()
            self._dynamodb = self._aws_factory.create_dynamodb()

            self._initialized = True
            self._notify_observers(EventType.CONFIGURATION_VALIDATED, {"config": config})

            logger.info("AWS XGBoost service initialized successfully")

        except Exception as e:
            self._notify_observers(EventType.CONFIGURATION_ERROR, {"error": str(e)})
            if isinstance(e, ConfigurationError | ServiceConfigurationError):
                raise
            raise ConfigurationError(f"Failed to initialize AWS XGBoost service: {e!s}") from e

    def is_initialized(self) -> bool:
        """Check if the service is properly initialized.

        Returns:
            True if initialized, False otherwise
        """
        return self._initialized

    def predict(
        self, patient_id: str, features: dict[str, Any], model_type: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Generic prediction method using AWS SageMaker.

        Args:
            patient_id: ID of the patient
            features: Dictionary of features for prediction
            model_type: Type of model to use for prediction
            **kwargs: Additional arguments for prediction

        Returns:
            Dictionary with prediction results

        Raises:
            ValidationError: If inputs are invalid
            ModelNotFoundError: If model is not found
            PredictionError: If prediction fails
        """
        self._ensure_initialized()

        try:
            self._notify_observers(
                EventType.PREDICTION_START, {"patient_id": patient_id, "model_type": model_type}
            )

            # Validate inputs
            self._validate_prediction_inputs(patient_id, features, model_type)

            # Get model endpoint
            endpoint_name = self._get_model_endpoint(model_type)

            # Prepare prediction payload
            payload = self._prepare_prediction_payload(features, **kwargs)

            # Invoke SageMaker endpoint
            response = self._invoke_sagemaker_endpoint(endpoint_name, payload)

            # Process response
            result = self._process_prediction_response(response, patient_id, model_type)

            self._notify_observers(
                EventType.PREDICTION_SUCCESS,
                {"patient_id": patient_id, "model_type": model_type, "result": result},
            )

            return result

        except Exception as e:
            self._notify_observers(
                EventType.PREDICTION_FAILURE,
                {"patient_id": patient_id, "model_type": model_type, "error": str(e)},
            )

            if isinstance(e, ValidationError | ModelNotFoundError | PredictionError):
                raise
            raise PredictionError(
                f"Prediction failed for patient {patient_id}: {e!s}", model_type=model_type
            ) from e

    def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        features: dict[str, Any] | None = None,
        clinical_data: dict[str, Any] | None = None,
        time_frame_days: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Predict risk level using a risk model.

        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict
            features: Feature values for prediction (optional)
            clinical_data: Clinical data for prediction (optional)
            time_frame_days: Timeframe for risk prediction in days (optional)
            **kwargs: Additional prediction parameters

        Returns:
            Risk prediction result
        """
        # Combine features and clinical data
        combined_features = self._combine_risk_features(
            features or {}, clinical_data or {}, time_frame_days
        )

        # Use generic predict method with risk model type
        model_type = f"risk_{risk_type}"
        return self.predict(patient_id, combined_features, model_type, **kwargs)

    def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Predict response to a psychiatric treatment.

        Args:
            patient_id: Patient identifier
            treatment_type: Type of treatment
            treatment_details: Treatment details
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters

        Returns:
            Treatment response prediction result
        """
        # Combine treatment and clinical data
        combined_features = {**clinical_data, "treatment_type": treatment_type, **treatment_details}

        # Use generic predict method with treatment response model
        model_type = f"treatment_response_{treatment_type}"
        return self.predict(patient_id, combined_features, model_type, **kwargs)

    def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: dict[str, int],
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Predict clinical outcomes based on treatment plan.

        Args:
            patient_id: Patient identifier
            outcome_timeframe: Timeframe for outcome prediction
            clinical_data: Clinical data for prediction
            treatment_plan: Treatment plan details
            **kwargs: Additional prediction parameters

        Returns:
            Outcome prediction result
        """
        # Combine all data for outcome prediction
        combined_features = {**clinical_data, **treatment_plan, **outcome_timeframe}

        # Use generic predict method with outcome model
        model_type = "clinical_outcome"
        return self.predict(patient_id, combined_features, model_type, **kwargs)

    def get_feature_importance(
        self, patient_id: str, model_type: str, prediction_id: str
    ) -> dict[str, Any]:
        """Get feature importance for a prediction.

        Args:
            patient_id: Patient identifier
            model_type: Type of model
            prediction_id: Prediction identifier

        Returns:
            Feature importance data

        Raises:
            ResourceNotFoundError: If prediction is not found
        """
        self._ensure_initialized()

        try:
            # Retrieve prediction metadata from DynamoDB
            prediction_data = self._get_prediction_metadata(prediction_id)

            if not prediction_data:
                raise ResourceNotFoundError(
                    f"Prediction {prediction_id} not found",
                    resource_type="prediction",
                    resource_id=prediction_id,
                )

            # Get feature importance from model
            importance_data = self._compute_feature_importance(
                model_type, prediction_data["features"]
            )

            self._notify_observers(
                EventType.FEATURE_IMPORTANCE_COMPUTED,
                {
                    "patient_id": patient_id,
                    "model_type": model_type,
                    "prediction_id": prediction_id,
                },
            )

            return {
                "prediction_id": prediction_id,
                "patient_id": patient_id,
                "model_type": model_type,
                "feature_importance": importance_data,
                "timestamp": prediction_data.get("timestamp"),
            }

        except Exception as e:
            if isinstance(e, ResourceNotFoundError):
                raise
            raise PredictionError(
                f"Failed to get feature importance: {e!s}", model_type=model_type
            ) from e

    def get_available_models(self) -> list[dict[str, Any]]:
        """Get a list of available XGBoost models from AWS SageMaker.

        Returns:
            List of model information dictionaries
        """
        self._ensure_initialized()

        if self._sagemaker is None:
            raise ConfigurationError("SageMaker client not initialized")

        try:
            # List SageMaker endpoints
            response = self._sagemaker.list_endpoints(StatusEquals="InService", MaxResults=100)

            models = []
            for endpoint in response.get("Endpoints", []):
                model_info = {
                    "name": endpoint["EndpointName"],
                    "status": endpoint["EndpointStatus"],
                    "creation_time": endpoint["CreationTime"].isoformat(),
                    "last_modified_time": endpoint["LastModifiedTime"].isoformat(),
                }

                # Get additional model details
                try:
                    endpoint_config = self._sagemaker.describe_endpoint_config(
                        EndpointConfigName=endpoint["EndpointConfigName"]
                    )
                    model_info["instance_type"] = endpoint_config["ProductionVariants"][0][
                        "InstanceType"
                    ]
                except Exception:
                    # Continue if we can't get endpoint config details
                    pass

                models.append(model_info)

            return models

        except Exception as e:
            raise ServiceConnectionError(
                f"Failed to get available models: {e!s}", service_name="sagemaker"
            ) from e

    def get_model_info(self, model_type: str) -> dict[str, Any]:
        """Get information about a model.

        Args:
            model_type: Type of model

        Returns:
            Model information

        Raises:
            ModelNotFoundError: If model is not found
        """
        self._ensure_initialized()

        if self._sagemaker is None:
            raise ConfigurationError("SageMaker client not initialized")

        try:
            endpoint_name = self._get_model_endpoint(model_type)

            # Get endpoint details
            endpoint_info = self._sagemaker.describe_endpoint(EndpointName=endpoint_name)

            # Get endpoint configuration
            config_info = self._sagemaker.describe_endpoint_config(
                EndpointConfigName=endpoint_info["EndpointConfigName"]
            )

            return {
                "model_type": model_type,
                "endpoint_name": endpoint_name,
                "status": endpoint_info["EndpointStatus"],
                "creation_time": endpoint_info["CreationTime"].isoformat(),
                "last_modified_time": endpoint_info["LastModifiedTime"].isoformat(),
                "instance_type": config_info["ProductionVariants"][0]["InstanceType"],
                "instance_count": config_info["ProductionVariants"][0]["InitialInstanceCount"],
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationException":
                raise ModelNotFoundError(
                    f"Model {model_type} not found", model_type=model_type
                ) from e
            raise ServiceConnectionError(
                f"Failed to get model info: {e!s}", service_name="sagemaker"
            ) from e
        except Exception as e:
            raise PredictionError(f"Failed to get model info: {e!s}", model_type=model_type) from e

    def register_observer(self, event_type: EventType, observer: Observer) -> None:
        """Register an observer for a specific event type.

        Args:
            event_type: Type of event to observe
            observer: Observer to register
        """
        if event_type not in self._observers:
            self._observers[event_type] = []

        if observer not in self._observers[event_type]:
            self._observers[event_type].append(observer)

    def unregister_observer(self, event_type: EventType, observer: Observer) -> None:
        """Unregister an observer for a specific event type.

        Args:
            event_type: Type of event to stop observing
            observer: Observer to unregister
        """
        if event_type in self._observers and observer in self._observers[event_type]:
            self._observers[event_type].remove(observer)

    def _notify_observers(self, event_type: EventType, data: dict[str, Any]) -> None:
        """Notify all observers of an event.

        Args:
            event_type: Type of event that occurred
            data: Event data
        """
        for observer in self._observers.get(event_type, []):
            try:
                observer.update(event_type, data)
            except Exception as e:
                logger.warning(f"Observer notification failed: {e!s}")

    def _ensure_initialized(self) -> None:
        """Ensure the service is initialized.

        Raises:
            ConfigurationError: If service is not initialized
        """
        if not self._initialized:
            raise ConfigurationError("Service not initialized. Call initialize() first.")

    def _validate_config(self, config: dict[str, Any]) -> None:
        """Validate configuration.

        Args:
            config: Configuration to validate

        Raises:
            ConfigurationError: If configuration is invalid
        """
        required_keys = ["model_endpoints", "s3_bucket", "dynamodb_table"]

        for key in required_keys:
            if key not in config:
                raise ConfigurationError(f"Missing required configuration key: {key}", field=key)

        if not isinstance(config["model_endpoints"], dict):
            raise ConfigurationError(
                "model_endpoints must be a dictionary",
                field="model_endpoints",
                value=config["model_endpoints"],
            )

    def _validate_prediction_inputs(
        self, patient_id: str, features: dict[str, Any], model_type: str
    ) -> None:
        """Validate prediction inputs.

        Args:
            patient_id: Patient ID to validate
            features: Features to validate
            model_type: Model type to validate

        Raises:
            ValidationError: If inputs are invalid
        """
        if not patient_id or not isinstance(patient_id, str):
            raise ValidationError(
                "patient_id must be a non-empty string", field="patient_id", value=patient_id
            )

        if not features or not isinstance(features, dict):
            raise ValidationError(
                "features must be a non-empty dictionary", field="features", value=features
            )

        if not model_type or not isinstance(model_type, str):
            raise ValidationError(
                "model_type must be a non-empty string", field="model_type", value=model_type
            )

    def _get_model_endpoint(self, model_type: str) -> str:
        """Get SageMaker endpoint name for a model type.

        Args:
            model_type: Type of model

        Returns:
            SageMaker endpoint name

        Raises:
            ModelNotFoundError: If model endpoint is not configured
        """
        endpoints = self._config.get("model_endpoints", {})

        if model_type not in endpoints:
            raise ModelNotFoundError(
                f"No endpoint configured for model type: {model_type}", model_type=model_type
            )

        return str(endpoints[model_type])

    def _prepare_prediction_payload(self, features: dict[str, Any], **kwargs: Any) -> str:
        """Prepare prediction payload for SageMaker.

        Args:
            features: Feature dictionary
            **kwargs: Additional parameters

        Returns:
            JSON-serialized payload

        Raises:
            SerializationError: If payload cannot be serialized
        """
        try:
            payload = {"instances": [features], "configuration": kwargs}
            return json.dumps(payload)
        except Exception as e:
            raise SerializationError(
                f"Failed to serialize prediction payload: {e!s}",
                data_type="prediction_payload",
                format_type="json",
            ) from e

    def _invoke_sagemaker_endpoint(self, endpoint_name: str, payload: str) -> dict[str, Any]:
        """Invoke SageMaker endpoint.

        Args:
            endpoint_name: Name of the SageMaker endpoint
            payload: JSON payload for prediction

        Returns:
            SageMaker response

        Raises:
            ModelInvocationError: If endpoint invocation fails
            ModelTimeoutError: If endpoint times out
            ThrottlingError: If requests are throttled
        """
        if self._sagemaker_runtime is None:
            raise ConfigurationError("SageMaker runtime client not initialized")

        try:
            response = self._sagemaker_runtime.invoke_endpoint(
                EndpointName=endpoint_name, ContentType="application/json", Body=payload
            )

            # Read response body
            result = json.loads(response["Body"].read().decode())

            return {
                "predictions": result,
                "status_code": response["ResponseMetadata"]["HTTPStatusCode"],
                "request_id": response["ResponseMetadata"]["RequestId"],
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "ThrottlingException":
                raise ThrottlingError(
                    f"Requests throttled for endpoint {endpoint_name}",
                    service_name="sagemaker",
                    retry_after=60,
                ) from e
            elif error_code == "ModelError":
                raise ModelInvocationError(
                    f"Model error for endpoint {endpoint_name}: {e!s}",
                    endpoint_name=endpoint_name,
                    status_code=e.response["Error"].get("HTTPStatusCode"),
                ) from e
            else:
                raise ServiceConnectionError(
                    f"SageMaker error: {e!s}", service_name="sagemaker"
                ) from e
        except Exception as e:
            if "timeout" in str(e).lower():
                raise ModelTimeoutError(
                    f"Endpoint {endpoint_name} timed out",
                    endpoint_name=endpoint_name,
                    timeout_seconds=30,
                ) from e
            raise ModelInvocationError(
                f"Failed to invoke endpoint {endpoint_name}: {e!s}", endpoint_name=endpoint_name
            ) from e

    def _process_prediction_response(
        self, response: dict[str, Any], patient_id: str, model_type: str
    ) -> dict[str, Any]:
        """Process SageMaker prediction response.

        Args:
            response: SageMaker response
            patient_id: Patient ID
            model_type: Model type

        Returns:
            Processed prediction result
        """
        prediction_id = str(uuid.uuid4())

        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "model_type": model_type,
            "predictions": response["predictions"],
            "confidence": self._extract_confidence(response["predictions"]),
            "timestamp": self._get_current_timestamp(),
            "request_id": response.get("request_id"),
        }

        # Store prediction metadata in DynamoDB
        self._store_prediction_metadata(prediction_id, result)

        return result

    def _extract_confidence(self, predictions: Any) -> float | None:
        """Extract confidence score from predictions.

        Args:
            predictions: Prediction results

        Returns:
            Confidence score if available
        """
        try:
            if isinstance(predictions, list) and len(predictions) > 0:
                pred = predictions[0]
                if isinstance(pred, dict) and "confidence" in pred:
                    return float(pred["confidence"])
                elif isinstance(pred, dict) and "probability" in pred:
                    return float(pred["probability"])
            return None
        except Exception:
            return None

    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format.

        Returns:
            ISO formatted timestamp
        """
        from datetime import datetime

        return datetime.utcnow().isoformat()

    def _store_prediction_metadata(self, prediction_id: str, result: dict[str, Any]) -> None:
        """Store prediction metadata in DynamoDB.

        Args:
            prediction_id: Prediction ID
            result: Prediction result
        """
        if self._dynamodb is None:
            logger.warning("DynamoDB client not initialized, skipping metadata storage")
            return

        try:
            table_name = self._config["dynamodb_table"]

            item = {
                "prediction_id": {"S": prediction_id},
                "patient_id": {"S": result["patient_id"]},
                "model_type": {"S": result["model_type"]},
                "timestamp": {"S": result["timestamp"]},
                "features": {"S": json.dumps(result.get("features", {}))},
                "predictions": {"S": json.dumps(result["predictions"])},
            }

            if result.get("confidence") is not None:
                item["confidence"] = {"N": str(result["confidence"])}

            self._dynamodb.put_item(TableName=table_name, Item=item)

        except Exception as e:
            logger.warning(f"Failed to store prediction metadata: {e!s}")

    def _get_prediction_metadata(self, prediction_id: str) -> dict[str, Any] | None:
        """Get prediction metadata from DynamoDB.

        Args:
            prediction_id: Prediction ID

        Returns:
            Prediction metadata if found
        """
        if self._dynamodb is None:
            logger.warning("DynamoDB client not initialized, cannot retrieve metadata")
            return None

        try:
            table_name = self._config["dynamodb_table"]

            response = self._dynamodb.get_item(
                TableName=table_name, Key={"prediction_id": {"S": prediction_id}}
            )

            if "Item" not in response:
                return None

            item = response["Item"]
            return {
                "prediction_id": item["prediction_id"]["S"],
                "patient_id": item["patient_id"]["S"],
                "model_type": item["model_type"]["S"],
                "timestamp": item["timestamp"]["S"],
                "features": json.loads(item["features"]["S"]),
                "predictions": json.loads(item["predictions"]["S"]),
                "confidence": float(item["confidence"]["N"]) if "confidence" in item else None,
            }

        except Exception as e:
            logger.warning(f"Failed to get prediction metadata: {e!s}")
            return None

    def _compute_feature_importance(
        self, model_type: str, features: dict[str, Any]
    ) -> dict[str, float]:
        """Compute feature importance for a prediction.

        Args:
            model_type: Type of model
            features: Feature values

        Returns:
            Feature importance scores
        """
        # This is a simplified implementation
        # In a real system, this would use SHAP or similar explainability tools
        importance = {}

        for feature_name in features.keys():
            # Placeholder importance calculation
            importance[feature_name] = abs(hash(f"{model_type}_{feature_name}")) % 100 / 100.0

        # Normalize to sum to 1.0
        total = sum(importance.values())
        if total > 0:
            importance = {k: v / total for k, v in importance.items()}

        return importance

    def _combine_risk_features(
        self, features: dict[str, Any], clinical_data: dict[str, Any], time_frame_days: int | None
    ) -> dict[str, Any]:
        """Combine features for risk prediction.

        Args:
            features: Base features
            clinical_data: Clinical data
            time_frame_days: Time frame for prediction

        Returns:
            Combined feature dictionary
        """
        combined = {**features, **clinical_data}

        if time_frame_days is not None:
            combined["time_frame_days"] = time_frame_days

        return combined

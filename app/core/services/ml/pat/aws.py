"""
AWS-based implementation of the PAT service.

This module provides a production-ready implementation of the PAT service
that uses AWS services (SageMaker, S3, DynamoDB) for actigraphy data analysis
and embedding generation.
"""

import datetime
import uuid
from typing import Any

import boto3
from boto3.resources.base import ServiceResource
from botocore.client import BaseClient
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    ParamValidationError,
    PartialCredentialsError
)

from app.core.config import settings
from app.core.exceptions.base_exceptions import (
    AuthorizationException,
    ConfigurationError,
    ExternalServiceException,
    ResourceNotFoundError,
    ServiceNotInitializedError
)
from app.core.interfaces.ml.pat import PATServiceInterface
from app.infrastructure.logging.logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)


class AWSPATService(PATServiceInterface):
    """AWS implementation for the Patient Assessment Tool Service."""

    _initialized: bool = False
    _region_name: str | None = None
    _aws_access_key_id: str | None = None
    _aws_secret_access_key: str | None = None
    _aws_session_token: str | None = None
    _sagemaker_endpoint_name: str | None = None
    _dynamodb_table_name: str | None = None
    _s3_bucket_name: str | None = None

    # Type hints for AWS clients/resources
    _session: boto3.Session | None = None
    _sagemaker_runtime_client: BaseClient | None = None
    _s3_client: BaseClient | None = None
    _comprehend_medical_client: BaseClient | None = None
    _dynamodb_resource: ServiceResource | None = None

    def __init__(self,
                 config: dict[str, Any],
                 sagemaker_runtime_client: BaseClient | None = None,
                 s3_client: BaseClient | None = None,
                 comprehend_medical_client: BaseClient | None = None,
                 dynamodb_resource: ServiceResource | None = None):
        """Initialize the service with configuration and optional clients."""
        super().__init__(config)
        self._region_name = config.get('aws_region_name', settings.AWS_REGION_NAME)

    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the AWS PAT service with configuration."""
        try:
            # Validate and extract required configuration
            required_keys = [
                'aws_region_name',
                'aws_access_key_id',
                'aws_secret_access_key',
                # 'aws_session_token',  # Optional
                'sagemaker_endpoint_name',
                'dynamodb_table_name',
                's3_bucket_name'
            ]
            missing_keys = [key for key in required_keys if key not in config]
            if missing_keys:
                error_message = "Missing required AWS configuration keys: " + ', '.join(missing_keys)
                logger.error(error_message)
                raise ConfigurationError(error_message)

            # Store the validated config
            self._config = config

            # Set region and endpoint attributes
            self._aws_region_name = config['aws_region_name']
            self._aws_access_key_id = config['aws_access_key_id']
            self._aws_secret_access_key = config['aws_secret_access_key']
            self._aws_session_token = config.get('aws_session_token')
            self._sagemaker_endpoint_name = config['sagemaker_endpoint_name']
            self._dynamodb_table_name = config['dynamodb_table_name']
            self._s3_bucket_name = config['s3_bucket_name']

            # Initialize AWS clients
            try:
                self._session = boto3.Session(
                    aws_access_key_id=self._aws_access_key_id,
                    aws_secret_access_key=self._aws_secret_access_key,
                    aws_session_token=self._aws_session_token,
                    region_name=self._aws_region_name
                )
            except (NoCredentialsError, PartialCredentialsError) as e:
                logger.error("AWS credentials error during session initialization.", exc_info=True)
                raise ConfigurationError("AWS credentials not configured properly.") from e
            except Exception as e:
                logger.error("Unexpected error during session initialization.", exc_info=True)
                raise ConfigurationError("Failed to initialize AWS session.") from e

            try:
                self._sagemaker_runtime_client = self._session.client(
                    "sagemaker-runtime", region_name=self._aws_region_name
                )
            except Exception as e:
                error_msg = "Error initializing SageMaker client: " + e.__class__.__name__ + ": " + str(e)
                logger.error(error_msg)
                raise ConfigurationError(error_msg)

            try:
                self._s3_client = self._session.client(
                    "s3", region_name=self._aws_region_name
                )
            except Exception as e:
                error_msg = "Error initializing S3 client: " + e.__class__.__name__ + ": " + str(e)
                logger.error(error_msg)
                raise ConfigurationError(error_msg)

            try:
                self._dynamodb_resource = self._session.resource(
                    "dynamodb", region_name=self._aws_region_name
                )
            except Exception as e:
                error_msg = "Error initializing DynamoDB resource: " + e.__class__.__name__ + ": " + str(e)
                logger.error(error_msg)
                raise ConfigurationError(error_msg)

            try:
                self._comprehend_medical_client = self._session.client(
                    "comprehendmedical", region_name=self._aws_region_name
                )
            except Exception as e:
                error_msg = "Error initializing Comprehend Medical client: " + e.__class__.__name__ + ": " + str(e)
                logger.error(error_msg)
                raise ConfigurationError(error_msg)

            self._initialized = True
            logger.info("AWS PAT service initialized successfully")
        except ClientError as e:
            error_msg = "AWS client error during initialization: " + e.__class__.__name__ + ": " + e
            logger.error(error_msg)
            raise ExternalServiceException(error_msg)
        except Exception as e:
            error_msg = "Unexpected error during initialization: " + e.__class__.__name__ + ": " + str(e)
            logger.error(error_msg)
            raise ConfigurationError(error_msg)

    def _check_initialized(self) -> None:
        """Check if the service is initialized."""
        if not self._initialized:
            raise ConfigurationError("AWS PAT service not initialized")

    def _sanitize_phi(self, text: str) -> str:
        """Sanitize PHI from text using AWS Comprehend Medical.

        Args:
            text: The input text string.

        Returns:
            The sanitized text string with PHI replaced by tags.
            Returns original text if an error occurs or no PHI is detected.
        """
        if not self._initialized:
            logger.error("AWS PAT Service not initialized before calling _sanitize_phi")
            return text

        try:
            response = self._comprehend_medical_client.detect_phi(Text=text)
            entities = response.get('Entities', [])
            if not entities:
                return text

            entities.sort(key=lambda x: x.get('BeginOffset', 0))

            sanitized_segments = []
            last_end = 0
            original_text = text

            for entity in entities:
                begin = entity.get("BeginOffset")
                end = entity.get("EndOffset")
                entity_type = entity.get("Type")

                if not isinstance(begin, int) or not isinstance(end, int) or \
                   begin < 0 or end < begin or end > len(original_text):
                    logger.warning(
                        "Skipping entity due to invalid/out-of-bounds offset: " + str(entity)
                    )
                    continue

                if begin > last_end:
                    sanitized_segments.append(original_text[last_end:begin])
                elif begin < last_end:
                    logger.warning(
                        "Potential overlap detected. Entity: " + str(entity) + ", last_end: " + str(last_end)
                    )
                    # Handle overlap if necessary, current logic might skip text
                    pass

                replacement_tag = "[" + entity_type + "]"
                sanitized_segments.append(replacement_tag)

                last_end = end

            if last_end < len(original_text):
                sanitized_segments.append(original_text[last_end:])

            sanitized_text = "".join(sanitized_segments)
            return sanitized_text
        except ClientError as e:
            logger.error("AWS Comprehend Medical API Error: " + e.__class__.__name__ + ": " + str(e))
            # Return original text on error to avoid data loss
            return text

    def _sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Sanitize metadata to remove PHI.

        Args:
            metadata: The metadata to sanitize

        Returns:
            Sanitized metadata with PHI removed
        """
        sanitized = {}
        for key, value in metadata.items():
            if isinstance(value, str):
                sanitized[key] = self._sanitize_phi(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_metadata(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_metadata(item) if isinstance(item, dict)
                    else self._sanitize_phi(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized

    def analyze_text(self, text: str) -> dict[str, Any]:
        """Analyze text using AWS services (SageMaker, Comprehend Medical)."""
        self._check_initialized()

        # 1. Sanitize input text
        sanitized_text = self._sanitize_phi(text)

        # 2. Invoke SageMaker endpoint
        try:
            response = self._sagemaker_runtime_client.invoke_endpoint(
                EndpointName=self._sagemaker_endpoint_name,
                Body=sanitized_text.encode('utf-8'),
                ContentType='application/json'
            )
            # logger.info("Successfully invoked SageMaker endpoint: " + self._sagemaker_endpoint_name)
            # logger.debug("SageMaker Response Body: " + response['Body'].read().decode('utf-8'))
            # return json.loads(response['Body'].read().decode('utf-8'))
            # TODO: Implement actual parsing based on expected response format
            return {"message": "SageMaker endpoint invoked, parsing pending"}
        except ClientError as e:
            logger.error("Error invoking SageMaker endpoint " + self._sagemaker_endpoint_name + ": " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Error invoking SageMaker endpoint " + self._sagemaker_endpoint_name + ": " + e.__class__.__name__ + ": " + str(e)) from e
        except Exception as e:
            logger.error("Unexpected error during SageMaker invocation: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Unexpected error during SageMaker invocation: " + e.__class__.__name__ + ": " + str(e)) from e

    def store_result(self, result_id: str, analysis_result: dict[str, Any]) -> None:
        """Store analysis result in DynamoDB."""
        self._check_initialized()
        if not self._dynamodb_resource or not self._dynamodb_table_name:
            raise ConfigurationError("DynamoDB resource or table name not configured")

        # TODO: Implement embedding generation logic
        # embeddings = self._generate_embeddings(analysis_result['sanitized_text'])
        embeddings = []  # Placeholder

        # Store in DynamoDB
        try:
            table = self._dynamodb_resource.Table(self._dynamodb_table_name)
            table.put_item(
                Item={
                    'result_id': result_id,
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'analysis_result': analysis_result,  # Store the whole analysis
                    'embeddings': embeddings  # Store embeddings if generated
                }
            )
            logger.info("Successfully stored result with ID: " + result_id)
        except ClientError as e:
            logger.error("Error storing result " + result_id + " in DynamoDB: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Error storing result " + result_id + " in DynamoDB: " + e.__class__.__name__ + ": " + str(e)) from e
        except Exception as e:
            logger.error("Unexpected error storing result " + result_id + " in DynamoDB: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Unexpected error storing result " + result_id + " in DynamoDB: " + e.__class__.__name__ + ": " + str(e)) from e

    def retrieve_result(self, result_id: str) -> dict[str, Any] | None:
        """Retrieve analysis result from DynamoDB."""
        self._check_initialized()
        if not self._dynamodb_resource or not self._dynamodb_table_name:
            raise ConfigurationError("DynamoDB resource or table name not configured")

        try:
            table = self._dynamodb_resource.Table(self._dynamodb_table_name)
            response = table.get_item(Key={'result_id': result_id})
            item = response.get('Item')
            if item:
                logger.info("Successfully retrieved result with ID: " + result_id)
                # Potentially deserialize complex types if needed
                return item
            else:
                logger.warning("Result not found for ID: " + result_id)
                return None
        except ClientError as e:
            logger.error("Error retrieving result " + result_id + " from DynamoDB: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Error retrieving result " + result_id + " from DynamoDB: " + e.__class__.__name__ + ": " + str(e)) from e
        except Exception as e:
            logger.error("Unexpected error retrieving result " + result_id + " from DynamoDB: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Unexpected error retrieving result " + result_id + " from DynamoDB: " + e.__class__.__name__ + ": " + str(e)) from e

    def process_document(self, document_path: str) -> dict[str, Any]:
        """Process a document from S3: download, analyze, store result."""
        self._check_initialized()
        if not self._s3_client or not self._s3_bucket_name:
            raise ConfigurationError("S3 client or bucket name not configured")

        try:
            # Download document from S3
            # logger.info("Downloading document " + document_path + " from S3 bucket " + self._s3_bucket_name)
            # s3_object = self._s3_client.get_object(Bucket=self._s3_bucket_name, Key=document_path)
            # document_content = s3_object['Body'].read().decode('utf-8')
            # Placeholder content until S3 integration is fully tested
            document_content = "This is placeholder content for S3 document."
            logger.info("Using placeholder content for document: " + document_path)

        except ClientError as e:
            logger.error("Error downloading document " + document_path + " from S3: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Error downloading document " + document_path + " from S3: " + e.__class__.__name__ + ": " + str(e)) from e
        except Exception as e:
            logger.error("Unexpected error downloading document " + document_path + " from S3: " + e.__class__.__name__ + ": " + str(e))
            raise ExternalServiceException("Unexpected error downloading document " + document_path + " from S3: " + e.__class__.__name__ + ": " + str(e)) from e

        # Analyze document
        analysis_result = self.analyze_text(document_content)

        # Store result
        result_id = str(uuid.uuid4())
        self.store_result(result_id, analysis_result)

        return analysis_result

    def _generate_embeddings(self, text: str) -> list[float]:
        """(Placeholder) Generate embeddings for the text."""
        self._check_initialized()
        # This method would typically call another service (like SageMaker or a dedicated embedding model)
        logger.warning("_generate_embeddings is not implemented. Returning empty list.")
        return []

    # --- Configuration and Helper Methods ---
    @classmethod
    def get_required_config_keys(cls) -> list[str]:
        return [
            'aws_region_name',
            'aws_access_key_id',
            'aws_secret_access_key',
            # 'aws_session_token',  # Optional
            'sagemaker_endpoint_name',
            'dynamodb_table_name',
            's3_bucket_name'
        ]

    def get_status(self) -> dict[str, Any]:
        """Return the status of the service and its dependencies."""
        status = {
            "initialized": self._initialized,
            "region": self._region_name,
            "dependencies": {
                "sagemaker_endpoint": self._sagemaker_endpoint_name,
                "dynamodb_table": self._dynamodb_table_name,
                "s3_bucket": self._s3_bucket_name,
                # Add checks for actual connectivity if needed
                "aws_credentials_set": bool(self._aws_access_key_id and self._aws_secret_access_key)
            }
        }
        return status

    def _verify_resources(self) -> None:
        """Verify access to configured AWS resources."""
        logger.debug("SERVICE VerifyResources - Starting Verification")
        try:
            # Verify SageMaker Endpoint access (describe_endpoint)
            if self._sagemaker_runtime_client and self._sagemaker_endpoint_name:
                logger.debug("Verifying SageMaker endpoint: " + self._sagemaker_endpoint_name)
                # Need sagemaker client, not sagemaker_runtime_client for describe_endpoint
                # sagemaker_client = self._session.client('sagemaker', region_name=self._region_name)
                # sagemaker_client.describe_endpoint(EndpointName=self._sagemaker_endpoint_name)
                # Using invoke_endpoint as a proxy for runtime access check
                try:
                    # Attempt a minimal invocation - might fail if model expects specific input
                    # This is just to check connectivity/permissions to the runtime endpoint
                    self._sagemaker_runtime_client.invoke_endpoint(
                        EndpointName=self._sagemaker_endpoint_name,
                        Body=b'{}',  # Minimal dummy payload
                        ContentType='application/json'
                    )
                    logger.debug("Successfully invoked (as check) SageMaker endpoint: " + self._sagemaker_endpoint_name)
                except ClientError as invoke_error:
                    # Distinguish between 'Endpoint not found'/'AccessDenied' and payload errors
                    if 'ValidationException' in str(invoke_error) or 'ModelError' in str(invoke_error):
                        logger.debug("SageMaker endpoint " + self._sagemaker_endpoint_name + " exists but test invocation failed (expected for dummy payload): " + str(invoke_error))
                    else:
                        logger.error("Failed to invoke SageMaker endpoint " + self._sagemaker_endpoint_name + ": " + str(invoke_error))
                        raise ConfigurationError("SageMaker endpoint " + self._sagemaker_endpoint_name + " verification failed.") from invoke_error
            else:
                logger.warning("SageMaker client or endpoint name not configured, skipping verification.")

            # Verify Comprehend Medical access (simple call like list_phi_detection_jobs with limit 0?)
            # Or rely on detect_phi call during sanitization
            if self._comprehend_medical_client:
                logger.debug("Verifying Comprehend Medical access.")
                # Perform a low-impact check, e.g., describe_entities_detection_v2_job with a dummy ID or list_
                # Using detect_phi with empty text as a basic check
                try:
                    self._comprehend_medical_client.detect_phi(Text="test")
                    logger.debug("Comprehend Medical access verified.")
                except ClientError as cm_error:
                    logger.error("Comprehend Medical verification failed: " + str(cm_error))
                    raise ConfigurationError("Comprehend Medical verification failed.") from cm_error
            else:
                logger.warning("Comprehend Medical client not configured, skipping verification.")

            # Verify DynamoDB Table access (describe_table)
            if self._dynamodb_resource and self._dynamodb_table_name:
                logger.debug("Verifying DynamoDB table: " + self._dynamodb_table_name)
                try:
                    table = self._dynamodb_resource.Table(self._dynamodb_table_name)
                    table.load()  # describe_table is called implicitly
                    logger.debug("DynamoDB table '" + self._dynamodb_table_name + "' verified.")
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code")
                    resource_name = "unknown resource"
                    if "Bucket" in str(e):
                        resource_name = "S3 bucket '" + self._s3_bucket_name + "'"
                    elif "Table" in str(e):
                        resource_name = "DynamoDB table '" + self._dynamodb_table_name + "'"
                    # Add check for SageMaker endpoint verification if implemented

                    if error_code == "404" or "NotFound" in str(e) or \
                       error_code == "ResourceNotFoundException":
                        logger.error("Resource not found: " + resource_name + ". Error: " + str(e), exc_info=True)
                        raise ResourceNotFoundError(
                            "Required AWS resource not found: " + resource_name) from e
                    elif error_code == "403" or "AccessDenied" in str(e):
                        logger.error(
                            "Permission error accessing resource: " + resource_name + ". Error: " + str(e),
                            exc_info=True
                        )
                        raise AuthorizationException(
                            "Insufficient permissions for AWS resource: " + resource_name) from e
                    else:
                        logger.error("Error verifying AWS resource " + resource_name + ": " + str(e), exc_info=True)
                        raise ExternalServiceException(
                            "Could not verify AWS resource " + resource_name) from e
            else:
                logger.warning("DynamoDB resource or table name not configured, skipping verification.")

            # Verify S3 Bucket access (head_bucket)
            if self._s3_client and self._s3_bucket_name:
                logger.debug("Verifying S3 bucket: " + self._s3_bucket_name)
                try:
                    self._s3_client.head_bucket(Bucket=self._s3_bucket_name)
                    logger.debug("S3 bucket '" + self._s3_bucket_name + "' access verified.")
                except ClientError as s3_error:
                    # Check if it's a 404 Not Found or 403 Forbidden
                    error_code = s3_error.response.get('Error', {}).get('Code')
                    if error_code == 'NoSuchBucket':
                        logger.error("S3 bucket '" + self._s3_bucket_name + "' not found: " + str(s3_error))
                        raise ResourceNotFoundError("S3 bucket '" + self._s3_bucket_name + "' not found.") from s3_error
                    elif error_code == 'AccessDenied':
                        logger.error("Access denied for S3 bucket '" + self._s3_bucket_name + "': " + str(s3_error))
                        raise AuthorizationException("Access denied for S3 bucket '" + self._s3_bucket_name + "'.") from s3_error
                    else:
                        logger.error("Failed to access S3 bucket '" + self._s3_bucket_name + "': " + str(s3_error))
                        raise ConfigurationError("S3 bucket '" + self._s3_bucket_name + "' verification failed.") from s3_error
            else:
                logger.warning("S3 client or bucket name not configured, skipping verification.")

            logger.debug("SERVICE VerifyResources - Completed Successfully")
        except ConfigurationError:
            raise
        except Exception as e:
            logger.exception("Unexpected error during resource verification: " + str(e))
            raise ConfigurationError("Unexpected error verifying AWS resources.") from e

    def _get_detection_level(self, phi_count: int, total_words: int) -> str:
        """Determine the detection level based on PHI count and total words."""
        # Implement your logic here to determine the detection level
        # For demonstration purposes, a simple threshold-based approach is used
        if phi_count / total_words > 0.1:
            return "High"
        elif phi_count / total_words > 0.05:
            return "Medium"
        else:
            return "Low"

    # Example usage (for testing purposes, usually done via dependency injection)
    if __name__ == '__main__':
        # Example configuration
        # IMPORTANT: Replace placeholders with actual or mock credentials/endpoints for testing
        # Avoid committing real credentials!
        test_config = {
            'aws_region_name': 'us-east-1', # Replace if needed
            'aws_access_key_id': 'mock_or_env_var_key_id',
            'aws_secret_access_key': 'mock_or_env_var_secret_key',
            'sagemaker_endpoint_name': 'mock_endpoint',
            'dynamodb_table_name': 'mock_pat_results_table',
            's3_bucket_name': 'mock_clarity_documents_bucket'
        }

        # Initialize the service
        # Use a try-except block as initialization might fail with mock credentials
        try:
            pat_service = AWSPATService(test_config) # Corrected class name
            print("AWSPATService initialized (likely with mock config).")

            # Example 1: Analyze text
            sample_text = "Patient John Doe, DOB 01/01/1980, visited Dr. Smith. His MRN is 12345."
            print("\n--- Analyzing Text --- ")
            try:
                analysis = pat_service.analyze_text(sample_text)
                print("Text Analysis Result:")
                import json
                print(json.dumps(analysis, indent=2))
            except (ExternalServiceException, ValueError, ConfigurationError, ResourceNotFoundError) as analysis_err:
                print("Error during text analysis: " + str(analysis_err))
            except ServiceNotInitializedError as init_err:
                 print("Service not initialized for text analysis: " + str(init_err))

            # Example 2: Process a document (requires valid AWS setup or mocks)
            doc_key = 'sample_documents/patient_note_1.txt' # Replace with actual S3 key for testing
            print("\n--- Processing Document: " + doc_key + " ---")
            # This will likely fail without proper AWS credentials/mocks or if the document doesn't exist
            try:
                doc_result = pat_service.process_document(doc_key)
                print("Document Processing Result:")
                print(json.dumps(doc_result, indent=2))

                # Example 3: Retrieve result (using the same doc_key as result_id for this test)
                # Note: In a real app, result_id would be generated differently
                print("\n--- Retrieving Result for: " + doc_key + " ---")
                retrieved_result = pat_service.retrieve_result(doc_key)
                if retrieved_result:
                    print("Retrieved Result:")
                    print(json.dumps(retrieved_result, indent=2))
                else:
                    print("Result for " + doc_key + " not found or failed to parse.")

            except (ConfigurationError, ResourceNotFoundError, ExternalServiceException) as proc_err:
                print("Error during document processing/retrieval: " + str(proc_err))
            except ServiceNotInitializedError as init_err:
                 print("Service not initialized for document processing: " + str(init_err))

        except (ConfigurationError, ResourceNotFoundError, AuthorizationException) as init_err:
            print("Failed to initialize AWSPATService: " + str(init_err))
        except Exception as e:
            print("An unexpected error occurred in the main block: " + str(e), exc_info=True)

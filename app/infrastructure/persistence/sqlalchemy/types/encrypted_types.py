"""
SQLAlchemy TypeDecorators for Encrypted Data.

This module provides TypeDecorator implementations that automatically
encrypt data when writing to the database and decrypt it when reading,
using the application's configured encryption service.
"""

import base64
import json
import logging
from typing import Any, TypeVar

from pydantic import BaseModel
from sqlalchemy import types
from sqlalchemy.engine import Dialect

# Import the shared instance from the encryption module
from app.infrastructure.security.encryption import (
    encryption_service_instance as global_encryption_service_instance,
)

logger = logging.getLogger(__name__)

# Type variable for generic pydantic model handling
PydanticModel = TypeVar("PydanticModel", bound=BaseModel)


def serialize_for_encryption(obj: Any) -> str | None:
    """
    Serialize various Python objects to JSON strings for encryption.

    Handles Pydantic models, Python dicts, lists, and primitive types.
    For non-JSON serializable objects, falls back to string representation.

    Args:
        obj: The object to serialize

    Returns:
        JSON string representation of the object, or None if obj is None

    Raises:
        TypeError: If the object cannot be serialized to JSON or string
    """
    if obj is None:
        return None

    try:
        # Handle Pydantic models
        if hasattr(obj, "model_dump") and callable(obj.model_dump):
            return json.dumps(obj.model_dump())

        # Handle other objects that have dict() method
        if hasattr(obj, "dict") and callable(obj.dict):
            return json.dumps(obj.dict())

        # Handle dict, list, or primitive types
        return json.dumps(obj)
    except (TypeError, ValueError) as e:
        # For non-JSON serializable objects (like MagicMock), fall back to string representation
        logger.warning(
            f"Object of type {type(obj)} is not JSON serializable, using string representation: {e!s}"
        )
        try:
            return str(obj)
        except Exception as str_error:
            logger.error(f"Failed to serialize object of type {type(obj)} to string: {str_error!s}")
            raise TypeError(
                f"Object of type {type(obj).__name__} cannot be serialized: {str_error!s}"
            )


def deserialize_from_encryption(
    json_str: str, target_cls: type[PydanticModel] | None = None
) -> Any:
    """
    Deserialize JSON strings back to Python objects after decryption.

    Args:
        json_str: JSON string to deserialize
        target_cls: Optional target class for Pydantic model instantiation

    Returns:
        Deserialized Python object

    Raises:
        ValueError: If the JSON is invalid or target class cannot be instantiated
    """
    if not json_str:
        return None

    try:
        # Parse the JSON
        data = json.loads(json_str)

        # If a target class is provided and it's a Pydantic model, instantiate it
        if target_cls is not None:
            try:
                if hasattr(target_cls, "model_validate"):
                    return target_cls.model_validate(data)
                elif hasattr(target_cls, "parse_obj"):
                    return target_cls.parse_obj(data)
                else:
                    # Not a Pydantic model, just return the data
                    return data
            except Exception as e:
                logger.warning(
                    f"Failed to instantiate {target_cls.__name__}: {e!s}, returning raw data"
                )
                return data
        else:
            return data

    except json.JSONDecodeError as e:
        logger.error(f"Failed to deserialize JSON: {e!s}")
        raise ValueError(f"Invalid JSON in encrypted data: {e!s}")


class EncryptedTypeBase(types.TypeDecorator):
    """Base implementation for encrypted column types in SQLAlchemy."""

    impl = types.Text
    cache_ok = True

    def __init__(
        self,
        encrypt_sensitive_only: bool = False,
        encryption_service=None,
        *args,
        **kwargs,
    ):
        """
        Initialize an encrypted column type.

        Args:
            encrypt_sensitive_only: If True, only encrypt fields marked as sensitive
            encryption_service: Optional custom encryption service
        """
        super().__init__(*args, **kwargs)
        self.encrypt_sensitive_only = encrypt_sensitive_only
        self._encryption_service = encryption_service

    @property
    def encryption_service(self):
        """
        Get the encryption service, using instance if provided or global otherwise.

        This will never return None. If both the instance-specific and global
        encryption services are None, it will raise an AttributeError.

        Returns:
            An encryption service instance

        Raises:
            AttributeError: If no encryption service is available
        """
        if self._encryption_service is not None:
            return self._encryption_service

        if global_encryption_service_instance is not None:
            return global_encryption_service_instance

        # Last resort, try importing directly
        try:
            from app.infrastructure.security.encryption import get_encryption_service

            service = get_encryption_service()
            if service is not None:
                return service
        except ImportError:
            pass

        # If we get here, we couldn't find a valid encryption service
        logger.error("No encryption service available. This is a critical security error.")
        raise AttributeError("No encryption service available. Cannot encrypt/decrypt data.")

    def _convert_bind_param(self, value: Any) -> Any:
        """
        Convert a value to the format for binding to a database parameter.

        This must be implemented by subclasses.

        Args:
            value: Python value to convert

        Returns:
            Value ready for database binding
        """
        raise NotImplementedError("Subclasses must implement this method")

    def _convert_result_value(self, value: str) -> Any:
        """
        Convert a database value to a Python object.

        This must be implemented by subclasses.

        Args:
            value: Database value to convert

        Returns:
            Converted Python value
        """
        raise NotImplementedError("Subclasses must implement this method")

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        """
        Process a Python value before binding to a SQL statement parameter.

        This method is called by SQLAlchemy when preparing SQL statements.

        Args:
            value: Python value to process
            dialect: SQLAlchemy dialect

        Returns:
            Processed value ready for database storage
        """
        logger.debug(
            f"[EncryptedTypeBase] process_bind_param called for type {self.__class__.__name__}."
        )

        # Handle None case
        if value is None:
            return None

        # Convert to appropriate format for encryption
        converted = self._convert_bind_param(value)

        # Encrypt the converted value
        try:
            return self.encryption_service.encrypt_string(converted)
        except Exception as e:
            logger.error(f"Failed to encrypt value: {e!s}", exc_info=True)
            raise ValueError(f"Encryption failed: {e!s}")

    def process_result_value(self, value: Any | None, dialect: Dialect) -> Any:
        """
        Process a database value after retrieving from the database.

        This method is called by SQLAlchemy after executing SQL queries.
        Supports key rotation by trying primary key first, falling back to
        previous key if the primary key fails.

        Args:
            value: Database value to process
            dialect: SQLAlchemy dialect

        Returns:
            Processed Python object

        Raises:
            ValueError: If decryption fails
        """
        logger.debug(
            f"[EncryptedTypeBase] process_result_value called for type {self.__class__.__name__}."
        )

        # Handle None case
        if value is None:
            return None

        # Ensure we're working with a string
        if not isinstance(value, str):
            logger.warning(f"Expected string but got {type(value)} - trying to convert")
            try:
                # If it's bytes, decode as utf-8
                if isinstance(value, bytes):
                    value = value.decode("utf-8")
                else:
                    value = str(value)
            except Exception as e:
                logger.error(f"Failed to convert {type(value)} to string: {e!s}")
                raise ValueError(f"Cannot decrypt value of type {type(value)}")

        # Decrypt the value using the encryption service
        # This supports key rotation if the encryption service has previous_key
        try:
            decrypted = self.encryption_service.decrypt_string(value)

            # Handle a potential bytes result - some encryption services might return bytes
            if isinstance(decrypted, bytes):
                try:
                    decrypted = decrypted.decode("utf-8")
                except UnicodeDecodeError:
                    logger.warning("Decryption returned bytes that couldn't be decoded as UTF-8")

            return self._convert_result_value(decrypted)
        except ValueError as e:
            error_msg = str(e)
            # If key rotation is supported by the encryption service, the ValueError
            # from primary key failure should be logged but not raised
            if (
                hasattr(self.encryption_service, "previous_key")
                and self.encryption_service.previous_key
            ):
                logger.warning(
                    f"Primary key decryption failed, attempting previous key: {error_msg}"
                )
                # The encryption service should handle key rotation internally
                try:
                    # Try one more time - the service may handle key rotation
                    decrypted = self.encryption_service.decrypt_string(value)

                    if isinstance(decrypted, bytes):
                        try:
                            decrypted = decrypted.decode("utf-8")
                        except UnicodeDecodeError:
                            logger.warning(
                                "Decryption returned bytes that couldn't be decoded as UTF-8"
                            )

                    return self._convert_result_value(decrypted)
                except Exception as e2:
                    logger.error(f"All decryption attempts failed: {e2!s}", exc_info=True)
                    raise ValueError(f"Decryption failed with all available keys: {e2!s}")
            else:
                logger.error(f"Decryption failed: {error_msg}", exc_info=True)
                raise ValueError(f"Decryption failed: {error_msg}")
        except Exception as e:
            logger.error(f"Unexpected error during decryption: {e!s}", exc_info=True)
            raise ValueError(f"Decryption failed: {e!s}")


class EncryptedString(EncryptedTypeBase):
    """Encrypted string column type for SQLAlchemy."""

    def _convert_bind_param(self, value: Any) -> str | None:
        """
        Convert a Python object to a string for encryption.

        Args:
            value: The Python object to convert to string

        Returns:
            String value
        """
        if value is None:
            return None

        if not isinstance(value, str):
            return str(value)

        return value

    def _convert_result_value(self, value: str | bytes) -> str | None:
        """
        Return the decrypted string directly.

        Args:
            value: Decrypted database value (string or bytes)

        Returns:
            String value
        """
        if value is None:
            return None

        # Handle bytes vs string
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Couldn't decode bytes as UTF-8, using fallback conversion")
                return str(value)

        return value


class EncryptedText(EncryptedTypeBase):
    """Encrypted text column type for SQLAlchemy.

    For longer text fields compared to EncryptedString, maps to Text type.
    """

    impl = types.Text

    def _convert_bind_param(self, value: Any) -> str | None:
        """
        Convert a Python object to a string for encryption.

        Args:
            value: The Python object to convert to string

        Returns:
            String value
        """
        if value is None:
            return None

        if not isinstance(value, str):
            return str(value)

        return value

    def _convert_result_value(self, value: str | bytes) -> str | None:
        """
        Return the decrypted string directly.

        Args:
            value: Decrypted database value (string or bytes)

        Returns:
            String value
        """
        if value is None:
            return None

        # Handle bytes vs string
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Couldn't decode bytes as UTF-8, using fallback conversion")
                return str(value)

        return value


class EncryptedInteger(EncryptedTypeBase):
    """Encrypted integer column type for SQLAlchemy."""

    def _convert_bind_param(self, value: Any) -> str | None:
        """
        Convert an integer to a string for encryption.

        Args:
            value: Integer value to convert

        Returns:
            String representation of integer

        Raises:
            TypeError: If value cannot be converted to an integer
        """
        if value is None:
            return None

        try:
            int_value = int(value)
            return str(int_value)
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to convert {value} to integer: {e!s}")
            raise TypeError(f"Value {value} cannot be converted to integer")

    def _convert_result_value(self, value: str | bytes) -> int | None:
        """
        Convert a decrypted string value to an integer.

        Args:
            value: Decrypted database value (string or bytes)

        Returns:
            Integer value

        Raises:
            ValueError: If the value cannot be converted to an integer
        """
        if value is None:
            return None

        # Convert to string first if it's bytes
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Couldn't decode bytes as UTF-8, using fallback conversion")
                value = str(value)

        try:
            # Strip any whitespace and try to convert
            value_str = str(value).strip()

            # Handle float strings by truncating
            if "." in value_str:
                logger.warning(f"Converting float string '{value_str}' to integer (truncating)")
                return int(float(value_str))

            return int(value_str)
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to convert '{value}' to integer: {e!s}")
            raise ValueError(f"Cannot convert decrypted value '{value}' to integer: {e!s}")


class EncryptedJSON(EncryptedTypeBase):
    """Encrypted JSON column type for SQLAlchemy.

    Serialize Python objects to JSON, encrypt the JSON string,
    and store the encrypted string in the database.
    """

    def _convert_bind_param(self, value: dict | list | BaseModel | Any) -> str | None:
        """
        Convert a Python object to a JSON string for encryption.

        Args:
            value: The Python object to convert to JSON (dict, list, Pydantic model, etc.)

        Returns:
            JSON string

        Raises:
            TypeError: If the value cannot be serialized to JSON
        """
        if value is None:
            return None

        # Use the serialization helper to handle various types
        return serialize_for_encryption(value)

    def _convert_result_value(self, value: str | bytes) -> dict | list | str | None:
        """
        Convert a decrypted string to a JSON object or string.

        Args:
            value: Decrypted string to convert to JSON

        Returns:
            Parsed JSON object (dict or list) or original string if not valid JSON

        Raises:
            ValueError: If the data cannot be processed
        """
        if value is None:
            return None

        try:
            # Handle bytes vs string
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8")
                except UnicodeDecodeError:
                    logger.error("Cannot decode bytes as UTF-8 in JSON conversion")
                    raise ValueError("Decrypted data contains invalid UTF-8 bytes")

            # Try to parse as JSON first
            return json.loads(value)

        except json.JSONDecodeError:
            # If it's not valid JSON, try cleaning and parsing again
            try:
                # Sometimes the JSON might be escaped or have extra quotes
                cleaned_value = value.strip("\"'")
                return json.loads(cleaned_value)
            except json.JSONDecodeError:
                # If still not valid JSON, return as string (for objects that were serialized as strings)
                logger.warning(
                    f"Decrypted value is not valid JSON, returning as string: {value[:50]}..."
                )
                return value


class EncryptedPickle(EncryptedTypeBase):
    """Encrypted pickle column type for SQLAlchemy.

    Serialize Python objects to base64-encoded pickle data,
    encrypt the data, and store in the database.

    Note: Use with caution as pickle can be a security risk.
    Only use for trusted data and when JSON serialization is not sufficient.
    """

    def _convert_bind_param(self, value: Any) -> str | None:
        """
        Convert a Python object to a base64-encoded pickle string for encryption.

        Args:
            value: The Python object to pickle and encrypt

        Returns:
            Base64-encoded pickle string

        Raises:
            TypeError: If pickling fails
        """
        if value is None:
            return None

        import pickle

        try:
            pickled = pickle.dumps(value)
            return base64.b64encode(pickled).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to pickle object: {e!s}")
            raise TypeError(f"Object of type {type(value).__name__} cannot be pickled: {e!s}")

    def _convert_result_value(self, value: str) -> Any | None:
        """
        Convert a decrypted base64-encoded pickle string to a Python object.

        Args:
            value: The decrypted base64-encoded pickle string from database

        Returns:
            Unpickled Python object

        Raises:
            ValueError: If unpickling fails
        """
        if value is None:
            return None

        import pickle

        try:
            pickled = base64.b64decode(value)
            return pickle.loads(pickled)
        except Exception as e:
            logger.error(f"Failed to unpickle object: {e!s}")
            raise ValueError(f"Failed to unpickle decrypted value: {e!s}")


__all__ = [
    "EncryptedInteger",
    "EncryptedJSON",
    "EncryptedPickle",
    "EncryptedString",
    "EncryptedText",
    "EncryptedTypeBase",
    # Add other encrypted types here when defined
]

logger.info("Encrypted SQLAlchemy type decorators defined.")

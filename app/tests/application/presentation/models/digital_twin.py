"""
Digital Twin API models.

This module defines Pydantic models for API requests and responses
related to the digital twin system.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.presentation.models.biometric_data import BiometricDataOutput, PhysiologicalRangeModel


class BiometricTimeseriesOutput(BaseModel):
    """API model for biometric timeseries data."""
    
    biometric_type: str = Field(
        ...,
        description="Type of biometric data",
        example="heart_rate"
    )
    
    unit: str = Field(
        ...,
        description="Unit of measurement",
        example="bpm"
    )
    
    data_points: list[BiometricDataOutput] = Field(
        ...,
        description="Time series of biometric measurements",
        example=[{
            "timestamp": "2025-04-10T14:30:00",
            "value": 72.5,
            "source": "wearable",
            "metadata": {"device": "fitbit"}
        }]
    )
    
    physiological_range: PhysiologicalRangeModel | None = Field(
        default=None,
        description="Normal and critical ranges for this biometric",
        example={
            "min": 60.0,
            "max": 100.0,
            "critical_min": 40.0,
            "critical_max": 140.0
        }
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "biometric_type": "heart_rate",
            "unit": "bpm",
            "data_points": [
                {
                    "timestamp": "2025-04-10T14:30:00",
                    "value": 72.5,
                    "source": "wearable",
                    "metadata": {"device": "fitbit"}
                },
                {
                    "timestamp": "2025-04-10T15:30:00",
                    "value": 75.0,
                    "source": "wearable",
                    "metadata": {"device": "fitbit"}
                }
            ],
            "physiological_range": {
                "min": 60.0,
                "max": 100.0,
                "critical_min": 40.0,
                "critical_max": 140.0
            }
        }
    })


class DigitalTwinOutput(BaseModel):
    """API model for digital twin output."""
    
    id: str = Field(
        ...,
        description="Unique identifier for the digital twin",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    
    patient_id: str = Field(
        ...,
        description="ID of the associated patient",
        example="patient-123"
    )
    
    timeseries_data: dict[str, BiometricTimeseriesOutput] = Field(
        ...,
        description="Biometric timeseries data by type",
        example={
            "heart_rate": {
                "biometric_type": "heart_rate",
                "unit": "bpm",
                "data_points": [
                    {
                        "timestamp": "2025-04-10T14:30:00",
                        "value": 72.5,
                        "source": "wearable",
                        "metadata": {"device": "fitbit"}
                    }
                ],
                "physiological_range": {
                    "min": 60.0,
                    "max": 100.0,
                    "critical_min": 40.0,
                    "critical_max": 140.0
                }
            }
        }
    )
    
    created_at: datetime = Field(
        ...,
        description="When the digital twin was created",
        example="2025-03-15T00:00:00"
    )
    
    updated_at: datetime = Field(
        ...,
        description="When the digital twin was last updated",
        example="2025-04-10T14:30:00"
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "patient_id": "patient-123",
            "timeseries_data": {
                "heart_rate": {
                    "biometric_type": "heart_rate",
                    "unit": "bpm",
                    "data_points": [
                        {
                            "timestamp": "2025-04-10T14:30:00",
                            "value": 72.5,
                            "source": "wearable",
                            "metadata": {"device": "fitbit"}
                        }
                    ],
                    "physiological_range": {
                        "min": 60.0,
                        "max": 100.0,
                        "critical_min": 40.0,
                        "critical_max": 140.0
                    }
                },
                "blood_pressure": {
                    "biometric_type": "blood_pressure",
                    "unit": "mmHg",
                    "data_points": [
                        {
                            "timestamp": "2025-04-10T15:00:00",
                            "value": {"systolic": 120, "diastolic": 80},
                            "source": "clinical",
                            "metadata": {"position": "sitting"}
                        }
                    ],
                    "physiological_range": {
                        "min": 90.0,
                        "max": 120.0,
                        "critical_min": 70.0,
                        "critical_max": 180.0
                    }
                }
            },
            "created_at": "2025-03-15T00:00:00",
            "updated_at": "2025-04-10T15:00:00"
        }
    })


class DigitalTwinCreate(BaseModel):
    """API model for creating a new digital twin."""
    
    patient_id: str = Field(
        ...,
        description="ID of the associated patient",
        example="patient-123"
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "patient_id": "patient-123"
        }
    })


class DigitalTwinSummary(BaseModel):
    """API model for a summary view of a digital twin."""
    
    id: str = Field(
        ...,
        description="Unique identifier for the digital twin",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    
    patient_id: str = Field(
        ...,
        description="ID of the associated patient",
        example="patient-123"
    )
    
    latest_readings: dict[str, BiometricDataOutput] = Field(
        ...,
        description="Latest reading for each biometric type",
        example={
            "heart_rate": {
                "timestamp": "2025-04-10T14:30:00",
                "value": 72.5,
                "source": "wearable",
                "metadata": {"device": "fitbit"}
            },
            "blood_pressure": {
                "timestamp": "2025-04-10T15:00:00",
                "value": {"systolic": 120, "diastolic": 80},
                "source": "clinical",
                "metadata": {"position": "sitting"}
            }
        }
    )
    
    updated_at: datetime = Field(
        ...,
        description="When the digital twin was last updated",
        example="2025-04-10T15:00:00"
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "patient_id": "patient-123",
            "latest_readings": {
                "heart_rate": {
                    "timestamp": "2025-04-10T14:30:00",
                    "value": 72.5,
                    "source": "wearable",
                    "metadata": {"device": "fitbit"}
                },
                "blood_pressure": {
                    "timestamp": "2025-04-10T15:00:00",
                    "value": {"systolic": 120, "diastolic": 80},
                    "source": "clinical",
                    "metadata": {"position": "sitting"}
                }
            },
            "updated_at": "2025-04-10T15:00:00"
        }
    })
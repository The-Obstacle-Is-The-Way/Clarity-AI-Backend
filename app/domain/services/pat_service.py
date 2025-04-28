"""
Domain service interface for PAT (Pretrained Actigraphy Transformer).
Pure domain interface with no infrastructure dependencies.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID


class PATService(ABC):
    """
    Abstract interface for Pretrained Actigraphy Transformer operations.
    Concrete implementations will be provided in the infrastructure layer.
    """
    
    @abstractmethod
    async def process_actigraphy_data(
        self,
        patient_id: UUID,
        actigraphy_data: dict,
        data_source: str,
        start_time: datetime,
        end_time: datetime
    ) -> dict:
        """
        Process raw actigraphy data to extract behavioral patterns.
        
        Args:
            patient_id: UUID of the patient
            actigraphy_data: Raw data from wearable device
            data_source: Source of the data (e.g., "fitbit", "apple_watch")
            start_time: Start time of the data collection period
            end_time: End time of the data collection period
            
        Returns:
            Dictionary with extracted behavioral patterns and insights
        """
        pass
    
    @abstractmethod
    async def detect_activity_patterns(
        self,
        patient_id: UUID,
        time_period: str = "week",  # "day", "week", "month"
        granularity: str = "hourly"  # "minute", "hourly", "daily"
    ) -> list[dict]:
        """
        Detect activity patterns for a patient over a specified period.
        
        Args:
            patient_id: UUID of the patient
            time_period: Time period to analyze
            granularity: Granularity of the analysis
            
        Returns:
            List of detected activity patterns with metadata
        """
        pass
    
    @abstractmethod
    async def analyze_sleep_patterns(
        self,
        patient_id: UUID,
        days: int = 30
    ) -> dict:
        """
        Analyze sleep patterns for a patient over a specified number of days.
        
        Args:
            patient_id: UUID of the patient
            days: Number of days to analyze
            
        Returns:
            Dictionary with sleep pattern analysis
        """
        pass
    
    @abstractmethod
    async def detect_anomalies(
        self,
        patient_id: UUID,
        activity_type: str | None = None,  # "sleep", "movement", "heart_rate", etc.
        sensitivity: float = 0.8,  # 0.0 to 1.0
        time_range: tuple[datetime, datetime] | None = None
    ) -> list[dict]:
        """
        Detect anomalies in patient activity patterns.
        
        Args:
            patient_id: UUID of the patient
            activity_type: Optional type of activity to analyze
            sensitivity: Sensitivity of anomaly detection
            time_range: Optional time range for analysis
            
        Returns:
            List of detected anomalies with metadata
        """
        pass
    
    @abstractmethod
    async def extract_circadian_rhythms(
        self,
        patient_id: UUID,
        days: int = 30
    ) -> dict:
        """
        Extract circadian rhythm information from patient activity data.
        
        Args:
            patient_id: UUID of the patient
            days: Number of days to analyze
            
        Returns:
            Dictionary with circadian rhythm analysis
        """
        pass
    
    @abstractmethod
    async def correlate_activities_with_mood(
        self,
        patient_id: UUID,
        mood_data: dict,
        activity_data: dict | None = None,
        time_range: tuple[datetime, datetime] | None = None
    ) -> dict:
        """
        Correlate activity patterns with mood data.
        
        Args:
            patient_id: UUID of the patient
            mood_data: Dictionary with mood tracking data
            activity_data: Optional activity data (if not provided, fetched from database)
            time_range: Optional time range for analysis
            
        Returns:
            Dictionary with correlation analysis
        """
        pass
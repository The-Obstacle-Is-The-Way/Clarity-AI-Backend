"""
Pretrained Actigraphy Transformer (PAT) repository.

This module provides the repository implementation for storing and retrieving
PAT analysis results in a HIPAA-compliant manner.
"""

import json
import logging
import os
import uuid
from datetime import datetime
import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession

# Removed ml_settings import, will use get_settings
# from app.config.ml_settings import ml_settings 
from app.core.config.settings import get_settings
from app.core.exceptions.ml_exceptions import RepositoryError
from app.infrastructure.ml.pat.models import AnalysisResult, AnalysisTypeEnum
from app.core.domain.entities.actigraphy_analysis import ActigraphyAnalysis

logger = logging.getLogger(__name__)


class PATRepository:
    """
    Repository for PAT analysis results.
    
    This repository handles the storage and retrieval of PAT analysis results
    in a HIPAA-compliant manner, ensuring proper data segregation and access control.
    """
    
    def __init__(
        self,
        storage_path: str | None = None
    ):
        """
        Initialize the PAT repository.
        
        Args:
            storage_path: Path for storing analysis results (overrides settings)
        """
        settings = get_settings() # Get settings object
        # Use provided path or default from settings
        self.storage_path = storage_path or settings.ml.pat.results_storage_path
        
        # Create storage directory if it doesn't exist
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create patient subdirectories as needed
        self.patient_dir = os.path.join(self.storage_path, "patients")
        os.makedirs(self.patient_dir, exist_ok=True)
        
        # Create anonymous subdirectory for results without patient ID
        self.anonymous_dir = os.path.join(self.storage_path, "anonymous")
        os.makedirs(self.anonymous_dir, exist_ok=True)
    
    async def save_analysis_result(self, result: AnalysisResult) -> str:
        """
        Save an analysis result.
        
        Args:
            result: Analysis result to save
            
        Returns:
            ID of the saved analysis result
        """
        try:
            # Generate a unique ID if not provided
            if not result.analysis_id:
                result.analysis_id = str(uuid.uuid4())
            
            # Determine storage directory based on patient ID
            if result.patient_id:
                # Create patient directory if it doesn't exist
                patient_dir = os.path.join(self.patient_dir, result.patient_id)
                os.makedirs(patient_dir, exist_ok=True)
                
                # Create analysis type subdirectory
                analysis_type_dir = os.path.join(patient_dir, result.analysis_type.value)
                os.makedirs(analysis_type_dir, exist_ok=True)
                
                # Save result to file
                file_path = os.path.join(analysis_type_dir, f"{result.analysis_id}.json")
            else:
                # Create analysis type subdirectory in anonymous directory
                analysis_type_dir = os.path.join(self.anonymous_dir, result.analysis_type.value)
                os.makedirs(analysis_type_dir, exist_ok=True)
                
                # Save result to file
                file_path = os.path.join(analysis_type_dir, f"{result.analysis_id}.json")
            
            # Convert result to dictionary
            result_dict = result.dict()
            
            # Convert datetime objects to ISO format strings
            result_dict["timestamp"] = result_dict["timestamp"].isoformat()
            
            # Write result to file
            with open(file_path, "w") as f:
                json.dump(result_dict, f, indent=2)
            
            logger.info(f"Saved analysis result {result.analysis_id} to {file_path}")
            
            return result.analysis_id
        except Exception as e:
            logger.error(f"Error saving analysis result: {e}")
            raise RepositoryError(f"Failed to save analysis result: {e}")
    
    async def get_analysis_result(self, analysis_id: str, patient_id: str | None = None) -> AnalysisResult | None:
        """
        Get an analysis result by ID.
        
        Args:
            analysis_id: ID of the analysis result to retrieve
            patient_id: Optional patient ID for access control
            
        Returns:
            Retrieved analysis result or None if not found
        """
        try:
            # If patient ID is provided, look in patient directory
            if patient_id:
                patient_dir = os.path.join(self.patient_dir, patient_id)
                
                # Check each analysis type subdirectory
                for analysis_type in AnalysisTypeEnum:
                    analysis_type_dir = os.path.join(patient_dir, analysis_type.value)
                    file_path = os.path.join(analysis_type_dir, f"{analysis_id}.json")
                    
                    if os.path.exists(file_path):
                        with open(file_path) as f:
                            result_dict = json.load(f)
                        
                        # Convert ISO format strings to datetime objects
                        result_dict["timestamp"] = datetime.fromisoformat(result_dict["timestamp"])
                        
                        return AnalysisResult(**result_dict)
            
            # If not found in patient directory or patient ID not provided, look in anonymous directory
            for analysis_type in AnalysisTypeEnum:
                analysis_type_dir = os.path.join(self.anonymous_dir, analysis_type.value)
                file_path = os.path.join(analysis_type_dir, f"{analysis_id}.json")
                
                if os.path.exists(file_path):
                    with open(file_path) as f:
                        result_dict = json.load(f)
                    
                    # Convert ISO format strings to datetime objects
                    result_dict["timestamp"] = datetime.fromisoformat(result_dict["timestamp"])
                    
                    return AnalysisResult(**result_dict)
            
            # If not found anywhere, return None
            logger.warning(f"Analysis result {analysis_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error retrieving analysis result: {e}")
            raise RepositoryError(f"Failed to retrieve analysis result: {e}")
    
    async def get_patient_analysis_results(
        self,
        patient_id: str,
        analysis_type: AnalysisTypeEnum | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 10,
        skip: int = 0
    ) -> list[AnalysisResult]:
        """
        Get analysis results for a patient.
        
        Args:
            patient_id: ID of the patient
            analysis_type: Optional analysis type to filter by
            start_date: Optional start date for filtering results
            end_date: Optional end date for filtering results
            limit: Maximum number of results to return
            skip: Number of results to skip
            
        Returns:
            List of analysis results
        """
        try:
            patient_dir = os.path.join(self.patient_dir, patient_id)
            
            # Check if patient directory exists
            if not os.path.exists(patient_dir):
                logger.warning(f"Patient directory {patient_dir} not found")
                return []
            
            results = []
            
            # If analysis type is provided, only look in that subdirectory
            if analysis_type:
                analysis_type_dir = os.path.join(patient_dir, analysis_type.value)
                
                if os.path.exists(analysis_type_dir):
                    # Get all JSON files in the directory
                    file_paths = [
                        os.path.join(analysis_type_dir, f)
                        for f in os.listdir(analysis_type_dir)
                        if f.endswith(".json")
                    ]
                    
                    # Load each file and filter by date if needed
                    for file_path in file_paths:
                        with open(file_path) as f:
                            result_dict = json.load(f)
                        
                        # Convert ISO format strings to datetime objects
                        timestamp = datetime.fromisoformat(result_dict["timestamp"])
                        result_dict["timestamp"] = timestamp
                        
                        # Filter by date if needed
                        if start_date and timestamp < start_date:
                            continue
                        if end_date and timestamp > end_date:
                            continue
                        
                        results.append(AnalysisResult(**result_dict))
            else:
                # Look in all analysis type subdirectories
                for analysis_type in AnalysisTypeEnum:
                    analysis_type_dir = os.path.join(patient_dir, analysis_type.value)
                    
                    if os.path.exists(analysis_type_dir):
                        # Get all JSON files in the directory
                        file_paths = [
                            os.path.join(analysis_type_dir, f)
                            for f in os.listdir(analysis_type_dir)
                            if f.endswith(".json")
                        ]
                        
                        # Load each file and filter by date if needed
                        for file_path in file_paths:
                            with open(file_path) as f:
                                result_dict = json.load(f)
                            
                            # Convert ISO format strings to datetime objects
                            timestamp = datetime.fromisoformat(result_dict["timestamp"])
                            result_dict["timestamp"] = timestamp
                            
                            # Filter by date if needed
                            if start_date and timestamp < start_date:
                                continue
                            if end_date and timestamp > end_date:
                                continue
                            
                            results.append(AnalysisResult(**result_dict))
            
            # Sort results by timestamp (newest first)
            results.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Apply skip and limit
            return results[skip:skip + limit]
        except Exception as e:
            logger.error(f"Error retrieving patient analysis results: {e}")
            raise RepositoryError(f"Failed to retrieve patient analysis results: {e}")
    
    async def delete_analysis_result(self, analysis_id: str, patient_id: str | None = None) -> bool:
        """
        Delete an analysis result.
        
        Args:
            analysis_id: ID of the analysis result to delete
            patient_id: Optional patient ID for access control
            
        Returns:
            True if the result was deleted, False otherwise
        """
        try:
            # If patient ID is provided, look in patient directory
            if patient_id:
                patient_dir = os.path.join(self.patient_dir, patient_id)
                
                # Check each analysis type subdirectory
                for analysis_type in AnalysisTypeEnum:
                    analysis_type_dir = os.path.join(patient_dir, analysis_type.value)
                    file_path = os.path.join(analysis_type_dir, f"{analysis_id}.json")
                    
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Deleted analysis result {analysis_id} from {file_path}")
                        return True
            
            # If not found in patient directory or patient ID not provided, look in anonymous directory
            for analysis_type in AnalysisTypeEnum:
                analysis_type_dir = os.path.join(self.anonymous_dir, analysis_type.value)
                file_path = os.path.join(analysis_type_dir, f"{analysis_id}.json")
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted analysis result {analysis_id} from {file_path}")
                    return True
            
            # If not found anywhere, return False
            logger.warning(f"Analysis result {analysis_id} not found for deletion")
            return False
        except Exception as e:
            logger.error(f"Error deleting analysis result: {e}")
            raise RepositoryError(f"Failed to delete analysis result: {e}")
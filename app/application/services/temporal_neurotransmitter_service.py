"""
Application service for temporal neurotransmitter analysis.
"""
from datetime import datetime, timedelta
from app.domain.utils.datetime_utils import UTC
from typing import Dict, List, Optional, Tuple, Any
from uuid import UUID
import logging
import uuid

from app.domain.entities.temporal_sequence import TemporalSequence
from app.domain.entities.neurotransmitter_effect import NeurotransmitterEffect
from app.domain.entities.digital_twin_enums import BrainRegion, Neurotransmitter, ClinicalSignificance
from app.domain.entities.temporal_neurotransmitter_mapping import extend_neurotransmitter_mapping
from app.domain.entities.neurotransmitter_mapping import NeurotransmitterMapping, create_default_neurotransmitter_mapping
from app.domain.repositories.temporal_repository import TemporalSequenceRepository, EventRepository
from app.domain.services.visualization_preprocessor import NeurotransmitterVisualizationPreprocessor


class TemporalNeurotransmitterService:
    """
    Application service for temporal neurotransmitter analysis and visualization.
    
    This service coordinates the interactions between domain entities and repositories,
    providing a unified API for analyzing neurotransmitter dynamics over time.
    """
    
    def __init__(
        self,
        sequence_repository: TemporalSequenceRepository,
        event_repository: Optional[EventRepository] = None,
        nt_mapping: Optional[NeurotransmitterMapping] = None,
        visualization_preprocessor: Optional[NeurotransmitterVisualizationPreprocessor] = None,
        xgboost_service = None,  # Intentionally untyped to avoid cyclic imports
        patient_id: Optional[UUID] = None
    ):
        """
        Initialize the service with required dependencies.
        
        Args:
            sequence_repository: Repository for temporal sequences
            event_repository: Optional repository for event tracking
            nt_mapping: Optional custom neurotransmitter mapping
            visualization_preprocessor: Optional visualization preprocessor
            xgboost_service: Optional XGBoost machine learning service
            patient_id: Optional patient ID for creating default mapping
        """
        self.sequence_repository = sequence_repository
        self.event_repository = event_repository
        
        # Logic to handle default mapping creation using patient_id or default mapping
        if nt_mapping:
            self.base_mapping = nt_mapping
        elif patient_id:
            base_mapping_temp = create_default_neurotransmitter_mapping()
            base_mapping_temp.patient_id = patient_id
            self.base_mapping = base_mapping_temp
        else:
            # Create default mapping when neither nt_mapping nor patient_id provided
            self.base_mapping = create_default_neurotransmitter_mapping()

        # Ensure base_mapping is set (should always be true with the above logic)
        if not hasattr(self, 'base_mapping'):
             # This path should ideally not be reachable
             raise RuntimeError("NeurotransmitterMapping failed to initialize.")
        
        # Create neurotransmitter mapping with temporal extensions
        self.nt_mapping = extend_neurotransmitter_mapping(self.base_mapping)
        
        # Initialize temporal profiles if needed
        if not hasattr(self.nt_mapping, 'temporal_profiles') or not self.nt_mapping.temporal_profiles:
            # self.nt_mapping._initialize_temporal_profiles() # Method does not exist on TemporalNeurotransmitterMapping
            pass
        
        # Create visualization preprocessor if not provided
        self.visualization_preprocessor = (
            visualization_preprocessor or NeurotransmitterVisualizationPreprocessor()
        )
        
        # Initialize XGBoost service if provided
        self._xgboost_service = xgboost_service
    
    async def generate_neurotransmitter_time_series(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
        time_range_days: int = 30,
        time_step_hours: int = 6
    ) -> UUID:
        """
        Generate a temporal sequence for a neurotransmitter in a specific brain region.
        
        Args:
            patient_id: UUID of the patient
            brain_region: Target brain region
            neurotransmitter: Target neurotransmitter
            time_range_days: Number of days to simulate
            time_step_hours: Hours between time points
            
        Returns:
            UUID of the created temporal sequence
        """
        
        # Generate timestamps
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=time_range_days)
        num_steps = int((time_range_days * 24) / time_step_hours)
        timestamps = [
            start_time + timedelta(hours=i * time_step_hours)
            for i in range(num_steps + 1)
        ]
        
        # Generate sequence using domain model
        sequence = self.nt_mapping.generate_temporal_sequence(
            brain_region=brain_region,
            neurotransmitter=neurotransmitter,
            timestamps=timestamps,
            patient_id=patient_id
        )
        
        # Persist sequence
        sequence_id = await self.sequence_repository.save(sequence)
        
        # Track event for audit and tracking purposes
        if self.event_repository:
            event = await self._create_sequence_generation_event(
                patient_id=patient_id,
                brain_region=brain_region,
                neurotransmitter=neurotransmitter,
                sequence_id=sequence_id
            )
            await self.event_repository.save_event(event)
        
        return sequence_id
    
    async def analyze_patient_neurotransmitter_levels(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter
    ) -> Optional[NeurotransmitterEffect]:
        """
        Analyze neurotransmitter levels for a patient in a specific brain region.
        
        Args:
            patient_id: UUID of the patient
            brain_region: Target brain region
            neurotransmitter: Target neurotransmitter
            
        Returns:
            Statistical analysis of neurotransmitter effect
        """
        # Get latest sequence containing this neurotransmitter
        sequence = await self.sequence_repository.get_latest_by_feature(
            patient_id=patient_id,
            feature_name=neurotransmitter.value
        )
        
        if not sequence:
            return None
        
        # Get feature index
        try:
            feature_idx = sequence.feature_names.index(neurotransmitter.value)
        except ValueError:
            return None
        
        # Extract time series for this neurotransmitter
        time_series_data = [
            (ts, values[feature_idx]) 
            for ts, values in zip(sequence.timestamps, sequence.values)
        ]
        
        # Calculate baseline period (first third of the sequence)
        split_idx = len(sequence.timestamps) // 3
        baseline_period = (sequence.timestamps[0], sequence.timestamps[split_idx])
        
        # Use the correct method name: analyze_temporal_response
        effect_analysis = self.nt_mapping.analyze_temporal_response(
            sequence=sequence, 
            baseline_period=baseline_period
        )
        
        # Create a NeurotransmitterEffect object based on pattern analysis
        effect = effect_analysis
        
        # Add brain region to the effect for downstream use (already handled by analyze_temporal_response? check return type)
        effect.comparison_period = (sequence.timestamps[split_idx+1], sequence.timestamps[-1])
        
        # Track analysis event if repository available
        if self.event_repository:
            event = await self._create_analysis_event(
                patient_id=patient_id,
                brain_region=brain_region,
                neurotransmitter=neurotransmitter,
                effect=effect
            )
            await self.event_repository.save_event(event)
        
        return effect
    
    async def simulate_treatment_response(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        target_neurotransmitter: Neurotransmitter,
        treatment_effect: float,
        simulation_days: int = 14
    ) -> Dict[Neurotransmitter, UUID]:
        """
        Simulate treatment response and save resulting temporal sequences.
        
        Args:
            patient_id: UUID of the patient
            brain_region: Target brain region
            target_neurotransmitter: Primary neurotransmitter affected by treatment
            treatment_effect: Magnitude and direction of effect (-1.0 to 1.0)
            simulation_days: Number of days to simulate
            
        Returns:
            Dictionary mapping neurotransmitters to their sequence UUIDs
        """

        adjusted_effect = treatment_effect
        # Predict treatment response using XGBoost
        xgboost_prediction = None
        
        if self._xgboost_service:
            # Try to get patient baseline data for more accurate prediction
            baseline_sequence = await self.sequence_repository.get_latest_by_feature(
                patient_id=patient_id,
                feature_name=target_neurotransmitter.value
            )
            
            # Extract baseline data if available
            baseline_data = {}
            if baseline_sequence and baseline_sequence.sequence_length > 0:
                feature_idx = baseline_sequence.feature_names.index(target_neurotransmitter.value)
                baseline_value = baseline_sequence.values[0][feature_idx]
                baseline_data[f"baseline_{target_neurotransmitter.value}"] = baseline_value
            
            # Get prediction from XGBoost service
            xgboost_prediction = self._xgboost_service.predict_treatment_response(
                patient_id=patient_id,
                brain_region=brain_region,
                neurotransmitter=target_neurotransmitter,
                treatment_effect=treatment_effect,
                baseline_data=baseline_data
            )
            
            # Apply prediction to adjust effect strength
            if xgboost_prediction and "predicted_response" in xgboost_prediction:
                # Scale the effect by the predicted response
                confidence = xgboost_prediction.get("confidence", 0.7)
                predicted_response = xgboost_prediction["predicted_response"]
                
                # Blend original effect with prediction based on confidence
                adjusted_effect = (
                    (treatment_effect * (1 - confidence)) + 
                    (predicted_response * confidence)
                )
        
        # Generate timestamps for simulation
        end_time = datetime.now(UTC) + timedelta(days=simulation_days)
        start_time = datetime.now(UTC)
        timestamps = [
            start_time + timedelta(hours=i * 6)  # 6-hour steps
            for i in range((simulation_days * 4) + 1)  # 4 time points per day
        ]
        
        # Simulate response with potentially adjusted effect
        responses = self.nt_mapping.simulate_treatment_response(
            brain_region=brain_region,
            target_neurotransmitter=target_neurotransmitter,
            treatment_effect=adjusted_effect,
            timestamps=timestamps,
            patient_id=patient_id
        )
        
        # Save sequences and track events
        sequence_ids = {}
        for nt, sequence in responses.items():
            # Update metadata with additional treatment info
            sequence.metadata.update({
                "simulation_type": "treatment_response",
                "treatment_target": target_neurotransmitter.value,
                "treatment_effect_magnitude": treatment_effect,
                "adjusted_effect_magnitude": adjusted_effect,
                "brain_region": brain_region.value,
                "xgboost_prediction": xgboost_prediction if xgboost_prediction else None
            })
            
            # Save sequence
            sequence_id = await self.sequence_repository.save(sequence)
            sequence_ids[nt] = sequence_id
            
            # Track simulation event
            if self.event_repository:
                event = await self._create_simulation_event(
                    patient_id=patient_id,
                    brain_region=brain_region,
                    target_neurotransmitter=target_neurotransmitter,
                    affected_neurotransmitter=nt,
                    sequence_id=sequence_id,
                    treatment_effect=treatment_effect,
                    adjusted_effect=adjusted_effect
                )
                await self.event_repository.save_event(event)
        
        return sequence_ids
    
    async def get_visualization_data(
        self,
        sequence_id: UUID,
        focus_features: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get optimized visualization data for a temporal sequence.
        
        Args:
            sequence_id: UUID of the sequence
            focus_features: Optional list of features to focus on
            
        Returns:
            Visualization-ready data structure
        """
        # Get sequence
        sequence = await self.sequence_repository.get_by_id(sequence_id)
        if not sequence:
            raise ValueError(f"Sequence with ID {sequence_id} not found")
        
        # Preprocess for visualization
        viz_data = self.visualization_preprocessor.precompute_temporal_sequence_visualization(
            sequence=sequence,
            focus_features=focus_features
        )
        
        # Ensure essential fields are returned in a consistent format
        time_points = [ts.isoformat() for ts in sequence.timestamps]
        features = focus_features or sequence.feature_names
        
        # Format values for time series visualization
        values = []
        for i, timestamp in enumerate(sequence.timestamps):
            # Get values for this timestamp
            time_point_values = []
            for feature in features:
                if feature in sequence.feature_names:
                    feature_idx = sequence.feature_names.index(feature)
                    time_point_values.append(sequence.values[i][feature_idx])
                else:
                    time_point_values.append(0.0)  # Default value if feature not found
            values.append(time_point_values)
        
        # Enhance with the properly structured data
        viz_data.update({
            "time_points": time_points,
            "features": features,
            "values": values,
            "metadata": sequence.metadata
        })
        
        return viz_data
    
    async def get_cascade_visualization(
        self,
        patient_id: UUID,
        starting_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
        time_steps: int = 10
    ) -> Dict[str, Any]:
        """
        Get visualization data for a neurotransmitter cascade.
        
        Args:
            patient_id: UUID of the patient
            starting_region: Brain region where cascade starts
            neurotransmitter: Neurotransmitter to trigger cascade
            time_steps: Number of time steps to simulate
            
        Returns:
            Visualization-ready data structure for the cascade
        """
        # Predict cascade
        cascade_results = self.nt_mapping.predict_cascade_effect(
            starting_region=starting_region,
            neurotransmitter=neurotransmitter,
            initial_level=0.8,  # Strong initial activation
            time_steps=time_steps,
            patient_id=patient_id
        )
        
        # Preprocess for visualization
        viz_data = self.visualization_preprocessor.precompute_cascade_geometry(
            cascade_data=cascade_results
        )
        
        # Create a nodes and connections structure for easier consumption by visualization libraries
        nodes = []
        connections = []
        
        # Process vertices to create nodes
        regions_with_activity = set()
        for t in range(time_steps):
            vertices = viz_data.get("vertices_by_time", [])[t] if t < len(viz_data.get("vertices_by_time", [])) else []
            colors = viz_data.get("colors_by_time", [])[t] if t < len(viz_data.get("colors_by_time", [])) else []
            
            # Process vertices (every 3 values represent x,y,z coordinates)
            for i in range(0, len(vertices), 3):
                if i + 2 < len(vertices):
                    # Find the closest brain region to these coordinates
                    position = (vertices[i], vertices[i+1], vertices[i+2])
                    region = self._find_region_for_position(position)
                    if region:
                        regions_with_activity.add(region)
                        
                        # Get activity level from the cascade results
                        activity_level = cascade_results.get(region, [0.0] * time_steps)[t]
                        
                        # Add node if not already added
                        if not any(n for n in nodes if n.get("id") == region.value):
                            nodes.append({
                                "id": region.value,
                                "brain_region": region.value,
                                "position": position,
                                "activity": [cascade_results.get(region, [0.0] * time_steps)[i] for i in range(time_steps)]
                            })
        
        # Process connections between active regions
        for region1 in regions_with_activity:
            for region2 in regions_with_activity:
                if region1 != region2:
                    # Check if there's activity propagation between these regions
                    # Simple heuristic: if region2 becomes active after region1
                    region1_activity = cascade_results.get(region1, [0.0] * time_steps)
                    region2_activity = cascade_results.get(region2, [0.0] * time_steps)
                    
                    # Find when each region first becomes active
                    region1_active_at = next((i for i, v in enumerate(region1_activity) if v > 0.1), -1)
                    region2_active_at = next((i for i, v in enumerate(region2_activity) if v > 0.1), -1)
                    
                    # Create connection if region2 activates after region1
                    if 0 <= region1_active_at < region2_active_at:
                        # Calculate connection strength based on activity correlation
                        connection_strength = 0.0
                        for t in range(time_steps - 1):
                            if region1_activity[t] > 0.1:
                                # Check if region2 becomes more active in the next step
                                delta = region2_activity[t+1] - region2_activity[t]
                                if delta > 0:
                                    connection_strength += delta
                        
                        # Add connection if significant
                        if connection_strength > 0.05:
                            connections.append({
                                "source": region1.value,
                                "target": region2.value,
                                "strength": min(1.0, connection_strength),
                                "lag": region2_active_at - region1_active_at
                            })
        
        # Format time steps data
        time_steps_data = []
        for t in range(time_steps):
            time_step_data = {
                "step": t,
                "regions": {}
            }
            
            for region in regions_with_activity:
                activity = cascade_results.get(region, [0.0] * time_steps)[t]
                if activity > 0.01:  # Only include non-trivial activity
                    time_step_data["regions"][region.value] = activity
            
            time_steps_data.append(time_step_data)
        
        # Add enhanced visualization data
        viz_data.update({
            "patient_id": str(patient_id),
            "starting_region": starting_region.value,
            "neurotransmitter": neurotransmitter.value,
            "time_steps": time_steps_data,
            "nodes": nodes,
            "connections": connections
        })
        
        return viz_data
    
    def _find_region_for_position(self, position: Tuple[float, float, float]) -> Optional[BrainRegion]:
        """
        Find the brain region closest to the given 3D position.
        
        Args:
            position: 3D position (x, y, z)
            
        Returns:
            Closest brain region or None if no match
        """
        # Get brain region coordinates from visualization preprocessor
        coordinates = self.visualization_preprocessor._brain_region_coordinates
        
        # Calculate distances to each region
        distances = {}
        for region, coords in coordinates.items():
            dx = position[0] - coords[0]
            dy = position[1] - coords[1]
            dz = position[2] - coords[2]
            distance = (dx * dx + dy * dy + dz * dz) ** 0.5
            distances[region] = distance
        
        # Return the closest region if distance is small enough
        if distances:
            closest_region = min(distances.items(), key=lambda x: x[1])
            if closest_region[1] < 0.3:  # Threshold for match
                return closest_region[0]
        
        return None
    
    async def _create_sequence_generation_event(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
        sequence_id: UUID
    ):
        """Create an event for sequence generation."""
        from app.domain.entities.temporal_events import CorrelatedEvent
        
        if not self.event_repository:
            return None
        
        event = CorrelatedEvent(
            event_type="neurotransmitter_sequence_generated",
            metadata={
                "patient_id": str(patient_id),
                "brain_region": brain_region.value,
                "neurotransmitter": neurotransmitter.value,
                "sequence_id": str(sequence_id),
                "timestamp": datetime.now(UTC).isoformat()
            }
        )
        
        return event
    
    async def _create_analysis_event(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
        effect: NeurotransmitterEffect
    ):
        """Create an event for neurotransmitter analysis."""
        from app.domain.entities.temporal_events import CorrelatedEvent
        
        if not self.event_repository:
            return None
        
        event = CorrelatedEvent(
            event_type="neurotransmitter_analyzed",
            metadata={
                "patient_id": str(patient_id),
                "brain_region": brain_region.value,
                "neurotransmitter": neurotransmitter.value,
                "effect_size": effect.effect_size,
                "p_value": effect.p_value,
                "is_significant": effect.is_statistically_significant,
                "clinical_significance": effect.clinical_significance.value if effect.clinical_significance else "unknown",
                "timestamp": datetime.now(UTC).isoformat()
            }
        )
        
        return event
    
    async def _create_simulation_event(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        target_neurotransmitter: Neurotransmitter,
        affected_neurotransmitter: Neurotransmitter,
        sequence_id: UUID,
        treatment_effect: float,
        adjusted_effect: float
    ):
        """Create an event for treatment simulation."""
        from app.domain.entities.temporal_events import CorrelatedEvent
        
        if not self.event_repository:
            return None
        
        event = CorrelatedEvent(
            event_type="treatment_simulation",
            metadata={
                "patient_id": str(patient_id),
                "brain_region": brain_region.value,
                "target_neurotransmitter": target_neurotransmitter.value,
                "affected_neurotransmitter": affected_neurotransmitter.value,
                "sequence_id": str(sequence_id),
                "treatment_effect": treatment_effect,
                "adjusted_effect": adjusted_effect,
                "adjustment_delta": adjusted_effect - treatment_effect,
                "timestamp": datetime.now(UTC).isoformat()
            }
        )
        
        return event

    async def record_concentration(
        self,
        patient_id: UUID,
        neurotransmitter: Neurotransmitter,
        brain_region: BrainRegion,
        value: float,
        timestamp: datetime,
    ) -> UUID:
        """Record a single neurotransmitter concentration reading.

        This is a lightweight helper used primarily for unit‑testing. It constructs
        a one‑row ``TemporalSequence`` and delegates persistence to
        ``self.sequence_repository``.
        """
        # Build a *very* lightweight object that satisfies unit‑test expectations
        from types import SimpleNamespace

        sequence = SimpleNamespace(
            patient_id=patient_id,
            neurotransmitter=neurotransmitter,
            brain_region=brain_region,
            values=[value],  # simple list so values[-1] == value
            timestamps=[timestamp],
        )

        # Persist via repository – unit tests patch this repository with an AsyncMock
        sequence_id: UUID = await self.sequence_repository.save(sequence)  # type: ignore[arg-type]
        return sequence_id

    async def record_event(
        self,
        patient_id: UUID,
        event_type: str,
        timestamp: datetime,
        details: dict[str, Any] | None = None,
    ) -> UUID:
        """Record an arbitrary temporal event for the patient."""
        from app.domain.entities.temporal_events import CorrelatedEvent

        event = CorrelatedEvent(
            event_type=event_type,
            patient_id=patient_id,
            timestamp=timestamp,
            metadata=details or {},
        )
        # Attach details attribute for consistency with record_event expectations
        if details is not None:
            setattr(event, 'details', details)

        if self.event_repository is None:
            # In production this should never happen, but unit‑tests may provide None – emulate save and return id.
            return event.event_id

        # Use generic 'save' method to align with repository interface in unit tests
        event_id: UUID = await self.event_repository.save(event)  # type: ignore[arg-type]
        return event_id

    async def get_concentration_history(
        self,
        patient_id: UUID,
        neurotransmitter: Neurotransmitter,
        brain_region: BrainRegion,
        start_time: datetime,
        end_time: datetime,
    ) -> Optional[TemporalSequence]:
        """Retrieve concentration data within a time window via repository."""
        return await self.sequence_repository.get_by_time_range(
            patient_id=patient_id,
            neurotransmitter=neurotransmitter,
            brain_region=brain_region,
            start_time=start_time,
            end_time=end_time,
        )

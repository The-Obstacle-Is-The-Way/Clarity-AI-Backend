"""
Enhanced Digital Twin Demo

This script demonstrates the enhanced capabilities of the Novamind Digital Twin platform.
It showcases the integration of MentalLLaMA-33B, XGBoost, and PAT components
through the Enhanced Digital Twin Core Service.

Usage:
    python -m app.demo.enhanced_digital_twin_demo
"""
import asyncio
import datetime
import logging
import uuid
from uuid import UUID

from app.infrastructure.factories.enhanced_mock_digital_twin_factory import (
    EnhancedMockDigitalTwinFactory,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class EnhancedDigitalTwinDemo:
    """
    Demonstration of the Enhanced Digital Twin capabilities.

    This class showcases the integration of the three AI components
    (MentalLLaMA, XGBoost, PAT) through the Digital Twin Core Service,
    including knowledge graph and Bayesian belief network features.
    """

    def __init__(self):
        """Initialize the demo with mock services."""
        # Create all services using the factory
        (
            self.digital_twin_service,
            self.mental_llama_service,
            self.xgboost_service,
            self.pat_service,
        ) = EnhancedMockDigitalTwinFactory.create_enhanced_mock_services()

        logger.info("Enhanced Digital Twin Demo initialized")

    async def run_demo(self):
        """Run the full enhanced digital twin demonstration."""
        logger.info("Starting Enhanced Digital Twin demonstration")

        # Create a test patient
        patient_id = uuid.uuid4()
        logger.info(f"Created test patient with ID: {patient_id}")

        # Step 1: Initialize Digital Twin
        await self.initialize_patient_digital_twin(patient_id)

        # Step 2: Process multimodal data
        await self.process_patient_data(patient_id)

        # Step 3: Perform various analyses
        await self.perform_advanced_analyses(patient_id)

        # Step 4: Generate visualizations
        await self.generate_visualizations(patient_id)

        # Step 5: Run counterfactual simulations
        await self.run_counterfactual_simulations(patient_id)

        # Step 6: Generate comprehensive clinical summary
        await self.generate_clinical_summary(patient_id)

        logger.info("Enhanced Digital Twin demonstration completed")

    async def initialize_patient_digital_twin(self, patient_id: UUID):
        """Initialize the patient's digital twin with initial data."""
        logger.info("Step 1: Initializing patient's Digital Twin")

        # Prepare initial data
        initial_data = {
            "diagnoses": ["Major Depressive Disorder", "Generalized Anxiety Disorder"],
            "symptoms": [
                "fatigue",
                "insomnia",
                "worry",
                "anhedonia",
                "psychomotor retardation",
            ],
            "medications": [
                {"name": "Escitalopram", "dosage": "10mg", "frequency": "daily"},
                {"name": "Bupropion", "dosage": "150mg", "frequency": "twice daily"},
            ],
            "vital_signs": {
                "heart_rate": 72,
                "blood_pressure": "120/80",
                "temperature": 98.6,
            },
            "demographics": {"age": 35, "gender": "female", "education_years": 16},
        }

        # Initialize the digital twin
        (
            digital_twin_state,
            knowledge_graph,
            belief_network,
        ) = await self.digital_twin_service.initialize_digital_twin(
            patient_id=patient_id,
            initial_data=initial_data,
            enable_knowledge_graph=True,
            enable_belief_network=True,
        )

        logger.info(
            f"Digital Twin initialized with {len(digital_twin_state.brain_regions)} brain regions"
        )
        logger.info(
            f"Knowledge graph initialized with {len(knowledge_graph.nodes)} nodes and {len(knowledge_graph.edges)} edges"
        )
        logger.info(
            f"Belief network initialized with {len(belief_network.variables)} variables"
        )

    async def process_patient_data(self, patient_id: UUID):
        """Process multimodal patient data."""
        logger.info("Step 2: Processing multimodal patient data")

        # Prepare multimodal data
        text_data = {
            "content": """
            Patient reports continued low mood and anxiety. Sleep has improved slightly with
            medication adjustments but still reports difficulties with middle insomnia.
            Appetite remains poor with 5-pound weight loss over past month. Denies suicidal
            ideation but describes passive thoughts that "life isn't worth living."
            Energy remains low and struggles to complete daily activities.
            """
        }

        physiological_data = {
            "heart_rate_variability": {
                "timestamp": datetime.datetime.now().isoformat(),
                "rmssd": 25.3,
                "sdnn": 42.8,
                "lf_hf_ratio": 1.8,
            },
            "sleep_data": {
                "total_sleep_time": 360,  # minutes
                "sleep_efficiency": 0.78,
                "rem_percentage": 0.15,
                "deep_sleep_percentage": 0.12,
                "awakenings": 5,
            },
        }

        behavioral_data = {
            "activity": {
                "steps_per_day": [3200, 2800, 4100, 3000, 2900, 3500, 2700],
                "active_minutes": [20, 15, 25, 18, 20, 22, 16],
            },
            "social_interaction": {
                "calls_per_day": [2, 1, 0, 3, 1, 0, 2],
                "texts_per_day": [15, 12, 8, 20, 10, 5, 18],
            },
        }

        genetic_data = {
            "variants": {
                "CYP2D6": "intermediate_metabolizer",
                "CYP2C19": "rapid_metabolizer",
                "COMT": "val/val",
                "MTHFR": "C677T heterozygous",
                "SLC6A4": "s/s",
            }
        }

        # Process the data through the Digital Twin
        (
            updated_state,
            results,
        ) = await self.digital_twin_service.process_multimodal_data(
            patient_id=patient_id,
            text_data=text_data,
            physiological_data=physiological_data,
            behavioral_data=behavioral_data,
            genetic_data=genetic_data,
        )

        logger.info(
            f"Processed multimodal data with {len(updated_state.clinical_insights)} total insights"
        )
        logger.info(f"Received {len(results)} processing results from AI components")

    async def perform_advanced_analyses(self, patient_id: UUID):
        """Perform various advanced analyses using the enhanced digital twin services."""
        logger.info("Step 3: Performing advanced analyses")

        # 3.1 Perform cross-validation of data points
        logger.info("3.1: Performing cross-validation")
        data_points = {
            "depression_severity": 0.75,
            "anxiety_severity": 0.65,
            "insomnia_severity": 0.60,
            "treatment_response": 0.40,
        }

        validation_results = await self.digital_twin_service.perform_cross_validation(
            patient_id=patient_id,
            data_points=data_points,
            validation_strategy="majority_vote",
        )

        logger.info(
            f"Cross-validation completed with strategy: {validation_results['validation_strategy']}"
        )

        # 3.2 Analyze temporal cascade
        logger.info("3.2: Analyzing temporal cascade")
        cascade_results = await self.digital_twin_service.analyze_temporal_cascade(
            patient_id=patient_id,
            start_event="Sleep Disruption",
            end_event="Mood Deterioration",
            max_path_length=4,
            min_confidence=0.6,
        )

        logger.info(f"Temporal cascade analysis found {len(cascade_results)} pathways")

        # 3.3 Map treatment effects
        logger.info("3.3: Mapping treatment effects")
        treatment_id = uuid.uuid4()

        # Generate time points for last 30 days
        now = datetime.datetime.now()
        time_points = [now - datetime.timedelta(days=i) for i in range(30, 0, -3)]

        treatment_effects = await self.digital_twin_service.map_treatment_effects(
            patient_id=patient_id,
            treatment_id=treatment_id,
            time_points=time_points,
            effect_types=["mood", "anxiety", "sleep", "energy"],
        )

        logger.info(
            f"Treatment effects mapping completed for treatment: {treatment_effects['treatment']['name']}"
        )

        # 3.4 Detect digital phenotype
        logger.info("3.4: Detecting digital phenotype")
        phenotype_results = await self.digital_twin_service.detect_digital_phenotype(
            patient_id=patient_id,
            data_sources=[
                "actigraphy",
                "heart_rate_variability",
                "sleep",
                "mood",
                "social",
            ],
            min_data_points=100,
            clustering_method="hierarchical",
        )

        logger.info(
            f"Digital phenotype detected: {phenotype_results['primary_phenotype']['phenotype']['name']}"
        )

        # 3.5 Generate predictive maintenance plan
        logger.info("3.5: Generating predictive maintenance plan")
        maintenance_plan = (
            await self.digital_twin_service.generate_predictive_maintenance_plan(
                patient_id=patient_id,
                risk_factors=[
                    "sleep_disruption",
                    "social_withdrawal",
                    "medication_adherence",
                ],
                prediction_horizon=90,
                intervention_options=[
                    {
                        "type": "medication_adjustment",
                        "description": "Adjust medication dosage",
                    },
                    {
                        "type": "therapy_session",
                        "description": "Schedule therapy session",
                    },
                    {
                        "type": "sleep_hygiene",
                        "description": "Implement sleep hygiene protocol",
                    },
                    {
                        "type": "social_activation",
                        "description": "Structured social activation",
                    },
                ],
            )
        )

        logger.info(
            f"Predictive maintenance plan generated with {len(maintenance_plan['intervention_recommendations'])} recommendations"
        )

    async def generate_visualizations(self, patient_id: UUID):
        """Generate visualization data for the digital twin."""
        logger.info("Step 4: Generating visualizations")

        # 4.1 Generate brain model visualization
        logger.info("4.1: Generating brain model visualization")
        brain_viz = await self.digital_twin_service.generate_visualization_data(
            patient_id=patient_id,
            visualization_type="brain_model",
            parameters={"highlight_significant": True, "show_connections": True},
        )

        logger.info(
            f"Brain model visualization generated with {len(brain_viz['regions'])} regions"
        )

        # 4.2 Generate intervention response coupling visualization
        logger.info("4.2: Generating intervention response coupling")
        response_coupling = (
            await self.digital_twin_service.generate_intervention_response_coupling(
                patient_id=patient_id,
                intervention_type="medication_adjustment",
                response_markers=["mood", "anxiety", "sleep_quality", "energy"],
                time_window=(0, 60),  # 60-day window
            )
        )

        logger.info(
            f"Intervention response coupling generated for: {response_coupling['intervention']}"
        )

    async def run_counterfactual_simulations(self, patient_id: UUID):
        """Run counterfactual simulations of different intervention scenarios."""
        logger.info("Step 5: Running counterfactual simulations")

        # Get the latest state id (mock)
        baseline_state_id = uuid.uuid4()

        # Define intervention scenarios
        intervention_scenarios = [
            {
                "name": "Medication Adjustment Scenario",
                "interventions": [
                    {
                        "type": "medication_adjustment",
                        "day": 0,
                        "details": "Increase Escitalopram to 15mg daily",
                        "affected_variables": ["mood", "anxiety"],
                        "effect_size": 0.3,
                    }
                ],
            },
            {
                "name": "Combined Therapy Scenario",
                "interventions": [
                    {
                        "type": "medication_adjustment",
                        "day": 0,
                        "details": "Increase Escitalopram to 15mg daily",
                        "affected_variables": ["mood", "anxiety"],
                        "effect_size": 0.25,
                    },
                    {
                        "type": "cognitive_behavioral_therapy",
                        "day": 7,
                        "details": "Weekly CBT sessions",
                        "affected_variables": ["mood", "anxiety", "sleep_quality"],
                        "effect_size": 0.2,
                    },
                ],
            },
            {
                "name": "Augmentation Strategy Scenario",
                "interventions": [
                    {
                        "type": "augmentation",
                        "day": 0,
                        "details": "Add Aripiprazole 2mg daily",
                        "affected_variables": ["mood", "energy"],
                        "effect_size": 0.35,
                    }
                ],
            },
        ]

        # Run the simulations
        simulation_results = (
            await self.digital_twin_service.perform_counterfactual_simulation(
                patient_id=patient_id,
                baseline_state_id=baseline_state_id,
                intervention_scenarios=intervention_scenarios,
                output_variables=[
                    "mood",
                    "anxiety",
                    "sleep_quality",
                    "energy",
                    "side_effects",
                ],
                simulation_horizon=180,  # 180-day horizon
            )
        )

        logger.info(
            f"Counterfactual simulations completed for {len(simulation_results)} scenarios"
        )

        # Log the top-ranked scenario
        top_scenario = simulation_results[0]
        logger.info(
            f"Top-ranked scenario: {top_scenario['scenario']['name']} with score {top_scenario['scenario_score']}"
        )

    async def generate_clinical_summary(self, patient_id: UUID):
        """Generate a comprehensive clinical summary."""
        logger.info("Step 6: Generating comprehensive clinical summary")

        # Generate the summary
        summary = await self.digital_twin_service.generate_multimodal_clinical_summary(
            patient_id=patient_id,
            summary_types=["status", "trajectory", "treatment", "risk", "prediction"],
            time_range=(
                datetime.datetime.now() - datetime.timedelta(days=90),
                datetime.datetime.now(),
            ),
            detail_level="comprehensive",
        )

        logger.info(
            f"Clinical summary generated with {len(summary['sections'])} sections"
        )
        logger.info(f"Generated at: {summary['metadata']['generated_at']}")


async def main():
    """Run the Enhanced Digital Twin demo."""
    demo = EnhancedDigitalTwinDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Digital Twin Demonstration Script

This script provides a complete demonstration of the Novamind Digital Twin platform,
showcasing how all components work together in a typical clinical workflow.

Run with: python -m app.demo.run_digital_twin_demo
"""
import asyncio
import json
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path

from app.domain.entities.patient import (
    Diagnosis,
    DiagnosisStatus,
    Gender,
    Medication,
    MedicationStatus,
    Patient,
)
from app.infrastructure.factories.mock_digital_twin_factory import MockDigitalTwinFactory


async def create_demo_patient():
    """Create a demo patient with realistic clinical data."""
    patient_id = uuid.uuid4()
    return Patient(
        id=patient_id,
        first_name="Alex",
        last_name="Morgan",
        date_of_birth=date.today() - timedelta(days=365 * 32),  # 32 years old
        gender=Gender.NON_BINARY,
        email="alex.morgan@example.com",
        phone="+1-555-987-6543",
        address="123 Main St, San Francisco, CA 94105",
        diagnoses=[
            Diagnosis(
                id=uuid.uuid4(),
                code="F33.1",
                name="Major depressive disorder, recurrent, moderate",
                status=DiagnosisStatus.CONFIRMED,
                diagnosed_date=date.today() - timedelta(days=365),
                notes="Previous episodes in 2020 and 2022"
            ),
            Diagnosis(
                id=uuid.uuid4(),
                code="F41.1",
                name="Generalized anxiety disorder",
                status=DiagnosisStatus.CONFIRMED,
                diagnosed_date=date.today() - timedelta(days=365)
            ),
            Diagnosis(
                id=uuid.uuid4(),
                code="G47.00",
                name="Insomnia disorder",
                status=DiagnosisStatus.CONFIRMED,
                diagnosed_date=date.today() - timedelta(days=180)
            )
        ],
        medications=[
            Medication(
                id=uuid.uuid4(),
                name="Escitalopram",
                dosage="10mg",
                frequency="daily",
                status=MedicationStatus.DISCONTINUED,
                start_date=date.today() - timedelta(days=270),
                end_date=date.today() - timedelta(days=90),
                notes="Discontinued due to side effects"
            ),
            Medication(
                id=uuid.uuid4(),
                name="Sertraline",
                dosage="50mg",
                frequency="daily",
                status=MedicationStatus.ACTIVE,
                start_date=date.today() - timedelta(days=60),
                notes="Tolerating well"
            ),
            Medication(
                id=uuid.uuid4(),
                name="Trazodone",
                dosage="50mg",
                frequency="as needed at bedtime",
                status=MedicationStatus.ACTIVE,
                start_date=date.today() - timedelta(days=30),
                notes="For insomnia"
            )
        ],
        # Patient class doesn't have these fields:
        # allergies, health_metrics, medical_history
    )


async def run_demo():
    """Run the full Digital Twin demonstration."""
    print("\n🧠 NOVAMIND DIGITAL TWIN DEMONSTRATION 🧠")
    print("=" * 50)
    print("Initializing system components...")
    
    # Create the system using our factory
    system = MockDigitalTwinFactory.create_complete_system()
    
    # Extract components
    patient_repo = system["repositories"]["patient_repository"]
    digital_twin_core = system["services"]["digital_twin_core"]
    xgboost_service = system["services"]["xgboost_service"]
    pat_service = system["services"]["pat_service"]
    mentalllama_service = system["services"]["mentalllama_service"]
    
    print("System initialized successfully!")
    print("=" * 50)
    
    # Create a demo patient
    print("\n1. Creating demo patient...")
    patient = await create_demo_patient()
    saved_patient = await patient_repo.save(patient)
    print(f"Created patient: {saved_patient.full_name}, ID: {saved_patient.id}")
    print(f"Diagnoses: {', '.join([d.name for d in saved_patient.diagnoses if d.is_active])}")
    print(f"Current medications: {', '.join([m.name for m in saved_patient.medications if m.is_active])}")
    
    # Initialize Digital Twin
    print("\n2. Initializing Digital Twin...")
    initial_state = await digital_twin_core.initialize_digital_twin(
        patient_id=saved_patient.id,
        initial_data={
            "clinical_metrics": {
                "phq9_score": 15,  # Moderate depression
                "gad7_score": 13,  # Moderate anxiety
                "insomnia_severity_index": 18,  # Moderate insomnia
                "mood_scale": 4,   # Scale 1-10
                "energy_scale": 3  # Scale 1-10
            },
            "metadata": {
                "initialized_by": "demo_script",
                "initial_assessment_date": datetime.now().isoformat()
            }
        }
    )
    print(f"Digital Twin initialized with state ID: {initial_state.id}")
    print(f"Initial metrics: PHQ-9 Score: {initial_state.clinical_metrics.get('phq9_score')}, " +
          f"GAD-7 Score: {initial_state.clinical_metrics.get('gad7_score')}")
    
    # Process simulated actigraphy data
    print("\n3. Processing one week of actigraphy data...")
    
    # Create realistic actigraphy data showing sleep disturbance and low activity
    actigraphy_data = {
        "start_time": (datetime.now() - timedelta(days=7)).isoformat(),
        "end_time": datetime.now().isoformat(),
        "daily_activity": [
            {
                "date": (datetime.now() - timedelta(days=i)).date().isoformat(),
                "steps": 3000 + (i * 500),  # Gradually increasing steps
                "active_minutes": 20 + (i * 5),  # Gradually increasing activity
                "sedentary_hours": 14 - (i * 0.5),  # Gradually decreasing sedentary time
                "calories_burned": 1800 + (i * 100)
            }
            for i in range(7)
        ],
        "sleep_data": [
            {
                "date": (datetime.now() - timedelta(days=i)).date().isoformat(),
                "duration_hours": 5.5 + (i * 0.2),  # Gradually improving sleep duration
                "onset_latency_minutes": 45 - (i * 3),  # Gradually improving sleep onset
                "awakenings": 4 - (i % 3),  # Variable awakenings
                "efficiency": 0.75 + (i * 0.02),  # Gradually improving efficiency
                "deep_sleep_percentage": 0.15 + (i * 0.01)
            }
            for i in range(7)
        ],
        "heart_rate_data": [
            {
                "date": (datetime.now() - timedelta(days=i)).date().isoformat(),
                "resting_hr": 78 - (i * 1),  # Gradually decreasing resting HR
                "average_hr": 85 - (i * 1),
                "max_hr": 120 - (i * 2),
                "min_hr": 65 - (i * 1),
                "hrv_ms": 35 + (i * 2)  # Gradually increasing HRV (improvement)
            }
            for i in range(7)
        ]
    }
    
    updated_state = await digital_twin_core.update_from_actigraphy(
        patient_id=saved_patient.id,
        actigraphy_data=actigraphy_data,
        data_source="wearable_device"
    )
    
    print(f"Processed actigraphy data, new state ID: {updated_state.id}")
    print(f"New Digital Twin version: {updated_state.version}")
    print(f"New clinical insights: {len(updated_state.clinical_insights)}")
    
    # Extract and display interesting insights
    sleep_insights = [i for i in updated_state.clinical_insights if "sleep" in i.title.lower()]
    activity_insights = [i for i in updated_state.clinical_insights if "activity" in i.title.lower()]
    
    if sleep_insights:
        print(f"\nSleep insight: {sleep_insights[0].title}")
        print(f"  {sleep_insights[0].description}")
    
    if activity_insights:
        print(f"\nActivity insight: {activity_insights[0].title}")
        print(f"  {activity_insights[0].description}")
    
    # Process clinical notes
    print("\n4. Processing clinical notes from recent session...")
    clinical_note = """
    Patient reports continued struggles with depressive symptoms, particularly low motivation 
    and anhedonia. Sleep has shown modest improvement in the past week, with sleep duration 
    increasing from approximately 5.5 to 6.5 hours per night and fewer nighttime awakenings.
    
    Anxiety symptoms remain prominent, especially around work performance and social interactions.
    Patient reports some benefit from mindfulness techniques practiced during the week.
    
    Sertraline was increased from 50mg to 100mg daily two weeks ago, and patient reports 
    tolerating the higher dose well with minimal side effects (mild nausea for the first 3 days).
    
    Patient is interested in cognitive behavioral therapy to complement medication management
    and has begun practicing some basic sleep hygiene techniques with modest benefit.
    
    No suicidal ideation, plan, or intent. No concerning changes in appetite or weight.
    
    Assessment: Recurrent MDD with moderate symptoms showing early response to treatment.
    Co-occurring GAD and insomnia with some improvement in sleep architecture.
    
    Plan:
    1. Continue Sertraline 100mg daily
    2. Continue Trazodone 50mg at bedtime as needed
    3. Refer for CBT evaluation
    4. Encourage daily physical activity, starting with 15-minute walks
    5. Follow-up in 3 weeks
    """
    
    clinician_id = uuid.uuid4()
    notes_state = await digital_twin_core.update_from_clinical_notes(
        patient_id=saved_patient.id,
        note_text=clinical_note,
        note_type="progress_note",
        clinician_id=clinician_id
    )
    
    print(f"Processed clinical notes, new state ID: {notes_state.id}")
    print(f"New Digital Twin version: {notes_state.version}")
    print(f"Total clinical insights: {len(notes_state.clinical_insights)}")
    
    # Display some new insights from the clinical notes
    new_insights = [i for i in notes_state.clinical_insights if i not in updated_state.clinical_insights]
    if new_insights:
        print("\nNew insights from clinical notes:")
        for idx, insight in enumerate(new_insights[:2]):  # Show just a couple
            print(f"{idx+1}. {insight.title} (confidence: {insight.confidence:.2f})")
            print(f"   {insight.description}")
    
    # Generate brain visualization data
    print("\n5. Generating 3D brain visualization data...")
    brain_data = await digital_twin_core.get_visualization_data(
        patient_id=saved_patient.id,
        visualization_type="brain_model"
    )
    
    print(f"Generated visualization with {len(brain_data['brain_regions'])} brain regions")
    print(f"Highlighted regions: {', '.join(brain_data['highlighted_regions'][:3])}...")
    print(f"Connectivity edges: {len(brain_data['connectivity'])}")
    
    # Generate treatment recommendations
    print("\n6. Generating treatment recommendations...")
    recommendations = await digital_twin_core.generate_treatment_recommendations(
        patient_id=saved_patient.id,
        include_rationale=True
    )
    
    print(f"Generated {len(recommendations)} treatment recommendations:")
    for idx, rec in enumerate(recommendations[:3]):  # Show top 3
        confidence = rec.get("confidence", 0) * 100
        efficacy = rec.get("predicted_efficacy", 0) * 100
        print(f"{idx+1}. {rec['type'].title()}: {rec['name']} " +
              f"(Confidence: {confidence:.1f}%, Predicted efficacy: {efficacy:.1f}%)")
        if "rationale" in rec:
            print(f"   Rationale: {rec['rationale']}")
    
    # Generate clinical summary
    print("\n7. Generating comprehensive clinical summary...")
    summary = await digital_twin_core.generate_clinical_summary(
        patient_id=saved_patient.id,
        include_treatment_history=True,
        include_predictions=True
    )
    
    print("Clinical summary generated.")
    print(f"Summary includes {len(summary.get('significant_insights', []))} significant insights")
    print(f"Summary includes {len(summary.get('treatment_recommendations', []))} recommendations")
    
    # Save outputs to files for review
    output_dir = Path("app/demo/output")
    output_dir.mkdir(exist_ok=True, parents=True)
    
    def json_serializer(obj):
        """Custom JSON serializer for objects not serializable by default json code"""
        if isinstance(obj, (datetime, UUID)):
            return str(obj)
        raise TypeError(f"Type {type(obj)} not serializable")
    
    # Save visualization data
    with open(output_dir / "brain_visualization.json", "w") as f:
        json.dump(brain_data, f, indent=2, default=json_serializer)
    
    # Save recommendations
    with open(output_dir / "treatment_recommendations.json", "w") as f:
        json.dump(recommendations, f, indent=2, default=json_serializer)
    
    # Save clinical summary
    with open(output_dir / "clinical_summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=json_serializer)
    
    print("\n8. Demo complete! Output files saved to app/demo/output/")
    print("\nIn a real deployment, these insights would be visualized in the Novamind")
    print("web interface, including the 3D brain model and treatment dashboards.")
    print("\nThank you for exploring the Novamind Digital Twin platform.")


if __name__ == "__main__":
    asyncio.run(run_demo())
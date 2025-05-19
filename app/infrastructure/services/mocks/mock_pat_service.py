"""
Mock implementation of PATService for testing.
Provides synthetic actigraphy analysis without requiring the actual PAT model.
"""
import random
from datetime import datetime, timedelta
from uuid import UUID

from app.domain.services.pat_service import PATService


class MockPATService(PATService):
    """
    Mock implementation of PATService.
    Generates synthetic actigraphy analysis for testing and development.
    """

    async def process_actigraphy_data(
        self,
        patient_id: UUID,
        actigraphy_data: dict,
        data_source: str,
        start_time: datetime,
        end_time: datetime,
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
        # Get data source type to adjust results
        data_source_lower = data_source.lower()

        # Initialize response structure
        response = {
            "patient_id": str(patient_id),
            "data_source": data_source,
            "analysis_timestamp": datetime.now().isoformat(),
            "collection_period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_hours": (end_time - start_time).total_seconds() / 3600,
            },
            "activity_patterns": [],
            "sleep_analysis": {},
            "behavioral_insights": [],
            "data_quality": {
                "completeness": round(random.uniform(0.85, 0.98), 2),
                "reliability_score": round(random.uniform(0.8, 0.95), 2),
            },
            "model_version": "mock-pat-v1.0",
        }

        # Generate synthetic activity patterns
        activity_periods = ["morning", "afternoon", "evening", "night"]
        activity_types = ["sedentary", "light", "moderate", "vigorous"]

        for period in activity_periods:
            # Different activity distributions for different times of day
            if period == "morning":
                weights = [0.3, 0.3, 0.3, 0.1]  # More active in morning
            elif period == "night":
                weights = [0.8, 0.15, 0.05, 0.0]  # Mostly sedentary at night
            else:
                weights = [0.4, 0.3, 0.2, 0.1]  # Balanced during day

            # Create activity distribution
            activity_dist = {}
            for i, activity in enumerate(activity_types):
                activity_dist[activity] = round(
                    weights[i] + random.uniform(-0.1, 0.1), 2
                )

            # Normalize to ensure sum is 1.0
            total = sum(activity_dist.values())
            for key in activity_dist:
                activity_dist[key] = round(activity_dist[key] / total, 2)

            # Add to response
            response["activity_patterns"].append(
                {
                    "time_period": period,
                    "activity_distribution": activity_dist,
                    "dominant_activity": max(activity_dist.items(), key=lambda x: x[1])[
                        0
                    ],
                    "confidence": round(random.uniform(0.7, 0.9), 2),
                }
            )

        # Generate synthetic sleep analysis
        sleep_metrics = {
            "average_sleep_duration": round(random.uniform(6.0, 8.5), 1),  # hours
            "sleep_efficiency": round(random.uniform(0.7, 0.95), 2),
            "sleep_onset_latency": round(random.uniform(10, 45), 1),  # minutes
            "wake_after_sleep_onset": round(random.uniform(15, 60), 1),  # minutes
            "sleep_fragmentation_index": round(random.uniform(10, 30), 1),
            "deep_sleep_percentage": round(random.uniform(0.15, 0.25), 2),
            "rem_sleep_percentage": round(random.uniform(0.2, 0.3), 2),
            "light_sleep_percentage": round(random.uniform(0.45, 0.6), 2),
            "sleep_regularity_index": round(random.uniform(0.6, 0.9), 2),
        }

        # Add daily pattern
        daily_patterns = []
        collection_days = (end_time - start_time).days

        for i in range(min(7, collection_days)):
            day_date = (start_time + timedelta(days=i)).date().isoformat()
            daily_patterns.append(
                {
                    "date": day_date,
                    "total_sleep": round(
                        sleep_metrics["average_sleep_duration"] + random.uniform(-1, 1),
                        1,
                    ),
                    "sleep_start": f"{23 - int(random.uniform(0, 2))}:{random.randint(0, 59):02d}",
                    "sleep_end": f"{7 + int(random.uniform(-1, 1))}:{random.randint(0, 59):02d}",
                    "awakenings": random.randint(1, 5),
                }
            )

        sleep_metrics["daily_patterns"] = daily_patterns
        response["sleep_analysis"] = sleep_metrics

        # Generate synthetic behavioral insights
        insights = []

        # Insight on activity level
        avg_sedentary = sum(
            p["activity_distribution"]["sedentary"]
            for p in response["activity_patterns"]
        ) / len(response["activity_patterns"])

        if avg_sedentary > 0.6:
            insights.append(
                {
                    "category": "activity",
                    "title": "High Sedentary Behavior",
                    "description": "Extended periods of sedentary behavior detected, which may impact mental health.",
                    "confidence_score": round(random.uniform(0.75, 0.9), 2),
                    "clinical_relevance": "moderate",
                    "recommendation": "Consider incorporating brief movement breaks throughout the day.",
                }
            )
        elif avg_sedentary < 0.4:
            insights.append(
                {
                    "category": "activity",
                    "title": "Healthy Activity Levels",
                    "description": "Regular movement patterns detected throughout the day.",
                    "confidence_score": round(random.uniform(0.8, 0.95), 2),
                    "clinical_relevance": "positive",
                    "recommendation": "Maintain current activity patterns.",
                }
            )

        # Insight on sleep
        if sleep_metrics["average_sleep_duration"] < 7.0:
            insights.append(
                {
                    "category": "sleep",
                    "title": "Insufficient Sleep Duration",
                    "description": "Average sleep duration below recommended levels for mental wellbeing.",
                    "confidence_score": round(random.uniform(0.8, 0.9), 2),
                    "clinical_relevance": "significant",
                    "recommendation": "Focus on sleep hygiene to extend sleep duration.",
                }
            )
        elif sleep_metrics["sleep_efficiency"] < 0.8:
            insights.append(
                {
                    "category": "sleep",
                    "title": "Poor Sleep Efficiency",
                    "description": "Sleep is fragmented with frequent awakenings.",
                    "confidence_score": round(random.uniform(0.75, 0.85), 2),
                    "clinical_relevance": "moderate",
                    "recommendation": "Consider sleep continuity interventions.",
                }
            )
        else:
            insights.append(
                {
                    "category": "sleep",
                    "title": "Adequate Sleep Patterns",
                    "description": "Sleep duration and quality within normal ranges.",
                    "confidence_score": round(random.uniform(0.8, 0.9), 2),
                    "clinical_relevance": "positive",
                    "recommendation": "Maintain current sleep habits.",
                }
            )

        # Insight on circadian rhythm
        sleep_regularity = sleep_metrics["sleep_regularity_index"]
        if sleep_regularity < 0.7:
            insights.append(
                {
                    "category": "circadian",
                    "title": "Irregular Sleep-Wake Pattern",
                    "description": "Inconsistent sleep and wake times detected.",
                    "confidence_score": round(random.uniform(0.75, 0.85), 2),
                    "clinical_relevance": "moderate",
                    "recommendation": "Establish consistent sleep and wake times.",
                }
            )

        response["behavioral_insights"] = insights

        return response

    async def detect_activity_patterns(
        self,
        patient_id: UUID,
        time_period: str = "week",  # "day", "week", "month"
        granularity: str = "hourly",  # "minute", "hourly", "daily"
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
        patterns = []

        # Generate synthetic activity patterns
        if granularity == "hourly":
            # Generate hourly activity patterns throughout a day
            hours_in_day = 24
            for hour in range(hours_in_day):
                # Generate different patterns based on time of day
                if 0 <= hour < 6:  # Night
                    dominant_activity = (
                        "sleep" if random.random() < 0.9 else "sedentary"
                    )
                    activity_level = random.uniform(0.0, 0.2)
                elif 6 <= hour < 9:  # Morning
                    activities = ["sedentary", "light", "moderate"]
                    weights = [0.5, 0.3, 0.2]
                    dominant_activity = random.choices(activities, weights=weights)[0]
                    activity_level = random.uniform(0.3, 0.7)
                elif 9 <= hour < 17:  # Daytime
                    activities = ["sedentary", "light", "moderate", "vigorous"]
                    weights = [0.6, 0.25, 0.1, 0.05]
                    dominant_activity = random.choices(activities, weights=weights)[0]
                    activity_level = random.uniform(0.4, 0.8)
                elif 17 <= hour < 21:  # Evening
                    activities = ["sedentary", "light", "moderate"]
                    weights = [0.7, 0.2, 0.1]
                    dominant_activity = random.choices(activities, weights=weights)[0]
                    activity_level = random.uniform(0.2, 0.6)
                else:  # Late evening
                    activities = ["sedentary", "sleep"]
                    weights = [0.8, 0.2]
                    dominant_activity = random.choices(activities, weights=weights)[0]
                    activity_level = random.uniform(0.1, 0.3)

                patterns.append(
                    {
                        "hour": hour,
                        "time_of_day": f"{hour:02d}:00",
                        "dominant_activity": dominant_activity,
                        "activity_level": round(activity_level, 2),
                        "step_count": int(activity_level * random.uniform(0, 2000)),
                        "heart_rate": int(60 + activity_level * random.uniform(0, 60)),
                        "confidence": round(random.uniform(0.75, 0.95), 2),
                    }
                )

        elif granularity == "daily":
            # Generate daily patterns
            days_to_generate = (
                7 if time_period == "week" else 30 if time_period == "month" else 1
            )

            for day in range(days_to_generate):
                # Some randomness for daily variations
                daily_activity_level = random.uniform(0.4, 0.8)

                # Weekend vs. weekday patterns
                is_weekend = day % 7 >= 5  # Saturday or Sunday
                if is_weekend:
                    activity_modifier = random.uniform(
                        -0.1, 0.2
                    )  # More variable on weekends
                else:
                    activity_modifier = random.uniform(
                        -0.05, 0.05
                    )  # More consistent on weekdays

                # Apply modifier
                adjusted_activity = max(
                    0.1, min(1.0, daily_activity_level + activity_modifier)
                )

                patterns.append(
                    {
                        "day": day + 1,
                        "date": (
                            datetime.now() - timedelta(days=days_to_generate - day)
                        )
                        .date()
                        .isoformat(),
                        "is_weekend": is_weekend,
                        "activity_level": round(adjusted_activity, 2),
                        "step_count": int(
                            adjusted_activity * random.uniform(5000, 15000)
                        ),
                        "active_hours": round(
                            adjusted_activity * random.uniform(8, 16), 1
                        ),
                        "sedentary_hours": round(
                            (1 - adjusted_activity) * random.uniform(8, 16), 1
                        ),
                        "activity_breakdown": {
                            "sedentary": round(
                                (1 - adjusted_activity) + random.uniform(-0.1, 0.1), 2
                            ),
                            "light": round(
                                adjusted_activity * 0.5 + random.uniform(-0.1, 0.1), 2
                            ),
                            "moderate": round(
                                adjusted_activity * 0.3 + random.uniform(-0.1, 0.1), 2
                            ),
                            "vigorous": round(
                                adjusted_activity * 0.2 + random.uniform(-0.1, 0.1), 2
                            ),
                        },
                    }
                )

        return patterns

    async def analyze_sleep_patterns(self, patient_id: UUID, days: int = 30) -> dict:
        """
        Analyze sleep patterns for a patient over a specified number of days.

        Args:
            patient_id: UUID of the patient
            days: Number of days to analyze

        Returns:
            Dictionary with sleep pattern analysis
        """
        # Generate synthetic sleep data
        daily_sleep = []

        # Base sleep parameters
        base_sleep_duration = random.uniform(6.5, 8.0)
        base_sleep_efficiency = random.uniform(0.75, 0.9)
        base_sleep_onset = random.uniform(20, 45)  # minutes
        base_awakenings = random.uniform(2, 6)

        # Create day-by-day synthetic data
        for day in range(days):
            # Add some daily variation
            day_modifier = random.uniform(-1.0, 1.0)

            # Sleep is usually worse on weekends
            is_weekend = day % 7 >= 5  # Saturday or Sunday
            weekend_modifier = -0.5 if is_weekend else 0

            # Calculate sleep metrics with variations
            sleep_duration = max(
                4.0,
                min(10.0, base_sleep_duration + day_modifier * 0.5 + weekend_modifier),
            )
            sleep_efficiency = max(
                0.6, min(0.98, base_sleep_efficiency + day_modifier * 0.05)
            )
            sleep_onset = max(
                5, min(90, base_sleep_onset + day_modifier * 10 + weekend_modifier * 15)
            )
            awakenings = max(0, min(10, base_awakenings + day_modifier))

            # Add to daily sleep data
            date = (datetime.now() - timedelta(days=days - day - 1)).date()

            # Random bedtime (earlier on weekdays, later on weekends)
            bedtime_hour = 22 if not is_weekend else 23
            bedtime_hour_variance = (
                random.uniform(-1, 1) if not is_weekend else random.uniform(-0.5, 2)
            )
            bedtime_min = random.randint(0, 59)
            bedtime = (
                f"{int(bedtime_hour + bedtime_hour_variance):02d}:{bedtime_min:02d}"
            )

            # Wake time based on sleep duration
            # Parse bedtime into datetime for calculation
            bedtime_dt = datetime.combine(
                date, datetime.strptime(bedtime, "%H:%M").time()
            )
            waketime_dt = bedtime_dt + timedelta(hours=sleep_duration)
            waketime = waketime_dt.strftime("%H:%M")

            daily_sleep.append(
                {
                    "date": date.isoformat(),
                    "sleep_duration_hours": round(sleep_duration, 2),
                    "sleep_efficiency": round(sleep_efficiency, 2),
                    "sleep_onset_minutes": round(sleep_onset, 1),
                    "awakenings": round(awakenings),
                    "bedtime": bedtime,
                    "wake_time": waketime,
                    "deep_sleep_percentage": round(random.uniform(0.15, 0.3), 2),
                    "rem_sleep_percentage": round(random.uniform(0.2, 0.35), 2),
                    "light_sleep_percentage": round(random.uniform(0.4, 0.6), 2),
                }
            )

        # Calculate overall statistics
        avg_sleep_duration = sum(
            day["sleep_duration_hours"] for day in daily_sleep
        ) / len(daily_sleep)
        avg_sleep_efficiency = sum(
            day["sleep_efficiency"] for day in daily_sleep
        ) / len(daily_sleep)
        avg_sleep_onset = sum(day["sleep_onset_minutes"] for day in daily_sleep) / len(
            daily_sleep
        )
        avg_awakenings = sum(day["awakenings"] for day in daily_sleep) / len(
            daily_sleep
        )

        # Calculate sleep regularity (consistency in bedtime and wake time)
        bedtimes = [
            datetime.strptime(day["bedtime"], "%H:%M").time() for day in daily_sleep
        ]
        bedtime_minutes = [(t.hour * 60 + t.minute) % (24 * 60) for t in bedtimes]

        waketimes = [
            datetime.strptime(day["wake_time"], "%H:%M").time() for day in daily_sleep
        ]
        waketime_minutes = [(t.hour * 60 + t.minute) for t in waketimes]

        # Calculate standard deviation in minutes
        bedtime_std = (
            sum(
                (x - sum(bedtime_minutes) / len(bedtime_minutes)) ** 2
                for x in bedtime_minutes
            )
            / len(bedtime_minutes)
        ) ** 0.5
        waketime_std = (
            sum(
                (x - sum(waketime_minutes) / len(waketime_minutes)) ** 2
                for x in waketime_minutes
            )
            / len(waketime_minutes)
        ) ** 0.5

        # Convert to regularity index (higher is better, max 1.0)
        bedtime_regularity = max(
            0, min(1, 1 - (bedtime_std / 120))
        )  # Scale: 0-2 hours std dev
        waketime_regularity = max(0, min(1, 1 - (waketime_std / 120)))

        # Combine into sleep regularity index
        sleep_regularity_index = (bedtime_regularity + waketime_regularity) / 2

        # Generate summary and insights
        sleep_quality_category = (
            "poor"
            if avg_sleep_efficiency < 0.75
            else "fair"
            if avg_sleep_efficiency < 0.85
            else "good"
        )

        sleep_insights = []
        if avg_sleep_duration < 7:
            sleep_insights.append("Sleep duration below recommended 7-9 hours")
        if avg_sleep_efficiency < 0.8:
            sleep_insights.append("Sleep efficiency below optimal threshold of 85%")
        if avg_sleep_onset > 30:
            sleep_insights.append("Extended sleep onset latency (>30 minutes)")
        if sleep_regularity_index < 0.7:
            sleep_insights.append("Irregular sleep-wake patterns detected")

        if not sleep_insights:
            sleep_insights.append("Sleep patterns within normal, healthy ranges")

        return {
            "patient_id": str(patient_id),
            "analysis_period": {
                "days": days,
                "start_date": daily_sleep[0]["date"],
                "end_date": daily_sleep[-1]["date"],
            },
            "summary": {
                "average_sleep_duration": round(avg_sleep_duration, 2),
                "average_sleep_efficiency": round(avg_sleep_efficiency, 2),
                "average_sleep_onset": round(avg_sleep_onset, 2),
                "average_awakenings": round(avg_awakenings, 2),
                "sleep_regularity_index": round(sleep_regularity_index, 2),
                "sleep_quality_category": sleep_quality_category,
            },
            "daily_sleep": daily_sleep,
            "insights": sleep_insights,
            "model_version": "mock-pat-v1.0",
        }

    async def detect_anomalies(
        self,
        patient_id: UUID,
        activity_type: str | None = None,  # "sleep", "movement", "heart_rate", etc.
        sensitivity: float = 0.8,  # 0.0 to 1.0
        time_range: tuple[datetime, datetime] | None = None,
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
        # Generate synthetic anomalies
        anomalies = []

        # Default to last 30 days if no time range specified
        if not time_range:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=30)
        else:
            start_time, end_time = time_range

        # Generate a small set of random anomalies
        num_anomalies = int(random.uniform(1, 5))  # 1-4 anomalies

        # More anomalies with higher sensitivity
        num_anomalies = max(1, min(10, int(num_anomalies * sensitivity * 2)))

        # Create anomaly dates
        anomaly_dates = []
        for _ in range(num_anomalies):
            # Random date within range
            days_range = (end_time - start_time).days
            random_day = random.randint(0, days_range)
            anomaly_date = start_time + timedelta(days=random_day)
            anomaly_dates.append(anomaly_date)

        # Generate anomalies
        for date in anomaly_dates:
            # Filter by activity type if specified
            if activity_type:
                if activity_type.lower() == "sleep":
                    anomalies.append(
                        {
                            "timestamp": date.isoformat(),
                            "activity_type": "sleep",
                            "anomaly_type": random.choice(
                                [
                                    "insufficient_duration",
                                    "fragmented_sleep",
                                    "delayed_onset",
                                ]
                            ),
                            "severity": round(random.uniform(0.7, 1.0), 2),
                            "confidence": round(
                                random.uniform(max(0.5, sensitivity), 0.95), 2
                            ),
                            "description": "Significant deviation from normal sleep pattern",
                            "metrics": {
                                "expected": {
                                    "duration_hours": round(
                                        random.uniform(7.0, 8.0), 1
                                    ),
                                    "efficiency": round(random.uniform(0.85, 0.95), 2),
                                },
                                "observed": {
                                    "duration_hours": round(
                                        random.uniform(4.0, 6.0), 1
                                    ),
                                    "efficiency": round(random.uniform(0.6, 0.75), 2),
                                },
                            },
                        }
                    )
                elif (
                    activity_type.lower() == "movement"
                    or activity_type.lower() == "activity"
                ):
                    anomalies.append(
                        {
                            "timestamp": date.isoformat(),
                            "activity_type": "movement",
                            "anomaly_type": random.choice(
                                [
                                    "extended_sedentary",
                                    "unusual_activity",
                                    "missing_data",
                                ]
                            ),
                            "severity": round(random.uniform(0.7, 1.0), 2),
                            "confidence": round(
                                random.uniform(max(0.5, sensitivity), 0.95), 2
                            ),
                            "description": "Abnormal movement pattern detected",
                            "metrics": {
                                "expected": {
                                    "active_minutes": round(random.uniform(180, 300)),
                                    "steps": round(random.uniform(7000, 10000)),
                                },
                                "observed": {
                                    "active_minutes": round(random.uniform(30, 120)),
                                    "steps": round(random.uniform(1000, 4000)),
                                },
                            },
                        }
                    )
                elif activity_type.lower() == "heart_rate":
                    anomalies.append(
                        {
                            "timestamp": date.isoformat(),
                            "activity_type": "heart_rate",
                            "anomaly_type": random.choice(
                                [
                                    "elevated_resting",
                                    "high_variability",
                                    "low_variability",
                                ]
                            ),
                            "severity": round(random.uniform(0.7, 1.0), 2),
                            "confidence": round(
                                random.uniform(max(0.5, sensitivity), 0.95), 2
                            ),
                            "description": "Unusual heart rate pattern detected",
                            "metrics": {
                                "expected": {
                                    "resting_hr": round(random.uniform(55, 70)),
                                    "hrv_ms": round(random.uniform(40, 60)),
                                },
                                "observed": {
                                    "resting_hr": round(random.uniform(75, 100)),
                                    "hrv_ms": round(random.uniform(20, 35)),
                                },
                            },
                        }
                    )
            else:
                # If no specific activity type, generate random anomalies
                activity_choices = ["sleep", "movement", "heart_rate"]
                chosen_activity = random.choice(activity_choices)

                if chosen_activity == "sleep":
                    anomalies.append(
                        {
                            "timestamp": date.isoformat(),
                            "activity_type": "sleep",
                            "anomaly_type": random.choice(
                                [
                                    "insufficient_duration",
                                    "fragmented_sleep",
                                    "delayed_onset",
                                ]
                            ),
                            "severity": round(random.uniform(0.7, 1.0), 2),
                            "confidence": round(
                                random.uniform(max(0.5, sensitivity), 0.95), 2
                            ),
                            "description": "Significant deviation from normal sleep pattern",
                        }
                    )
                elif chosen_activity == "movement":
                    anomalies.append(
                        {
                            "timestamp": date.isoformat(),
                            "activity_type": "movement",
                            "anomaly_type": random.choice(
                                [
                                    "extended_sedentary",
                                    "unusual_activity",
                                    "missing_data",
                                ]
                            ),
                            "severity": round(random.uniform(0.7, 1.0), 2),
                            "confidence": round(
                                random.uniform(max(0.5, sensitivity), 0.95), 2
                            ),
                            "description": "Abnormal movement pattern detected",
                        }
                    )
                elif chosen_activity == "heart_rate":
                    anomalies.append(
                        {
                            "timestamp": date.isoformat(),
                            "activity_type": "heart_rate",
                            "anomaly_type": random.choice(
                                [
                                    "elevated_resting",
                                    "high_variability",
                                    "low_variability",
                                ]
                            ),
                            "severity": round(random.uniform(0.7, 1.0), 2),
                            "confidence": round(
                                random.uniform(max(0.5, sensitivity), 0.95), 2
                            ),
                            "description": "Unusual heart rate pattern detected",
                        }
                    )

        return anomalies

    async def extract_circadian_rhythms(self, patient_id: UUID, days: int = 30) -> dict:
        """
        Extract circadian rhythm information from patient activity data.

        Args:
            patient_id: UUID of the patient
            days: Number of days to analyze

        Returns:
            Dictionary with circadian rhythm analysis
        """
        # Generate synthetic circadian rhythm data
        rhythm_data = {
            "patient_id": str(patient_id),
            "analysis_days": days,
            "timestamp": datetime.now().isoformat(),
            "sleep_phase": {
                "average_bedtime": f"{22 + int(random.uniform(-1, 2))}:{random.randint(0, 59):02d}",
                "average_wake_time": f"{7 + int(random.uniform(-1, 2))}:{random.randint(0, 59):02d}",
                "bedtime_consistency": round(
                    random.uniform(0.6, 0.9), 2
                ),  # 0.0-1.0 (higher is more consistent)
                "wake_time_consistency": round(random.uniform(0.65, 0.95), 2),
            },
            "activity_phase": {
                "peak_activity_time": f"{14 + int(random.uniform(-2, 2))}:{random.randint(0, 59):02d}",
                "activity_rhythm_strength": round(
                    random.uniform(0.5, 0.9), 2
                ),  # 0.0-1.0 (higher is stronger rhythm)
                "active_period_duration": round(random.uniform(13, 16), 1),  # hours
            },
            "phase_relationships": {
                "wake_to_activity_onset": round(random.uniform(1.5, 3.0), 1),  # hours
                "peak_activity_to_bedtime": round(random.uniform(6.0, 9.0), 1),  # hours
            },
            "rhythm_stability": {
                "overall_stability": round(random.uniform(0.6, 0.9), 2),  # 0.0-1.0
                "weekday_weekend_difference": round(
                    random.uniform(0.5, 2.0), 1
                ),  # hours
                "day_to_day_variation": round(random.uniform(0.5, 1.5), 1),  # hours
            },
            "model_version": "mock-pat-v1.0",
        }

        # Generate circadian metrics by hour
        hourly_metrics = []
        for hour in range(24):
            # Activity level follows a typical circadian pattern
            # Lower at night, higher during day with afternoon peak
            if 0 <= hour < 6:  # Night
                activity_level = random.uniform(0.05, 0.15)
            elif 6 <= hour < 9:  # Morning
                activity_level = 0.3 + (hour - 6) * 0.1 + random.uniform(-0.05, 0.05)
            elif 9 <= hour < 15:  # Day with afternoon peak
                activity_level = 0.5 + (hour - 9) * 0.05 + random.uniform(-0.1, 0.1)
            elif 15 <= hour < 21:  # Evening decline
                activity_level = 0.8 - (hour - 15) * 0.1 + random.uniform(-0.05, 0.05)
            else:  # Late evening
                activity_level = 0.2 - (hour - 21) * 0.05 + random.uniform(-0.03, 0.03)

            # Ensure within bounds
            activity_level = max(0.05, min(0.95, activity_level))

            # Generate heart rate following similar pattern
            base_hr = 60
            hr_range = 40
            heart_rate = base_hr + activity_level * hr_range + random.uniform(-5, 5)

            hourly_metrics.append(
                {
                    "hour": hour,
                    "time": f"{hour:02d}:00",
                    "activity_level": round(activity_level, 2),
                    "heart_rate": round(heart_rate),
                    "typical_state": "sleep"
                    if (0 <= hour < 7) or hour >= 22
                    else "active",
                }
            )

        rhythm_data["hourly_metrics"] = hourly_metrics

        # Generate rhythm insights
        insights = []

        # Assess rhythm stability
        if rhythm_data["rhythm_stability"]["overall_stability"] < 0.7:
            insights.append(
                {
                    "type": "stability",
                    "title": "Irregular Circadian Rhythm",
                    "description": "Day-to-day variability in sleep-wake patterns may impact well-being.",
                    "clinical_relevance": "moderate",
                    "recommendation": "Establish more consistent sleep and wake times.",
                }
            )

        # Assess weekday/weekend difference
        if rhythm_data["rhythm_stability"]["weekday_weekend_difference"] > 1.5:
            insights.append(
                {
                    "type": "social_jetlag",
                    "title": "Social Jetlag Detected",
                    "description": "Significant shift in sleep timing between weekdays and weekends.",
                    "clinical_relevance": "moderate",
                    "recommendation": "Minimize differences between weekday and weekend sleep schedules.",
                }
            )

        # Assess overall rhythm strength
        if rhythm_data["activity_phase"]["activity_rhythm_strength"] < 0.6:
            insights.append(
                {
                    "type": "rhythm_strength",
                    "title": "Weak Activity Rhythm",
                    "description": "Daily activity patterns show low amplitude/regularity.",
                    "clinical_relevance": "moderate",
                    "recommendation": "Strengthen daily routines with regular activity and light exposure.",
                }
            )

        # Add insights if any were generated
        if insights:
            rhythm_data["insights"] = insights
        else:
            rhythm_data["insights"] = [
                {
                    "type": "healthy_rhythm",
                    "title": "Healthy Circadian Pattern",
                    "description": "Circadian rhythm metrics fall within normal ranges.",
                    "clinical_relevance": "positive",
                    "recommendation": "Maintain current sleep-wake patterns.",
                }
            ]

        return rhythm_data

    async def correlate_activities_with_mood(
        self,
        patient_id: UUID,
        mood_data: dict,
        activity_data: dict | None = None,
        time_range: tuple[datetime, datetime] | None = None,
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
        # Generate synthetic correlation results
        # For a real implementation, this would analyze actual data

        correlations = {
            "overall_correlation": round(random.uniform(0.3, 0.7), 2),
            "confidence_level": round(random.uniform(0.7, 0.9), 2),
            "activity_mood_correlations": [
                {
                    "activity_type": "sleep_duration",
                    "correlation": round(random.uniform(0.4, 0.8), 2),
                    "lag_days": round(random.uniform(0, 1), 1),
                    "p_value": round(random.uniform(0.001, 0.05), 3),
                    "description": "Sleep duration shows significant correlation with mood patterns",
                },
                {
                    "activity_type": "physical_activity",
                    "correlation": round(random.uniform(0.3, 0.7), 2),
                    "lag_days": round(random.uniform(0, 2), 1),
                    "p_value": round(random.uniform(0.001, 0.05), 3),
                    "description": "Physical activity levels correlate with mood changes",
                },
                {
                    "activity_type": "social_activity",
                    "correlation": round(random.uniform(0.2, 0.6), 2),
                    "lag_days": round(random.uniform(0, 1), 1),
                    "p_value": round(random.uniform(0.01, 0.1), 3),
                    "description": "Social interaction patterns show some correlation with mood",
                },
            ],
            "time_of_day_effects": {
                "morning_activity_correlation": round(random.uniform(0.3, 0.7), 2),
                "afternoon_activity_correlation": round(random.uniform(0.2, 0.6), 2),
                "evening_activity_correlation": round(random.uniform(0.1, 0.5), 2),
            },
            "activity_thresholds": {
                "minimum_beneficial_activity_minutes": round(random.uniform(20, 40)),
                "optimal_sleep_hours": round(random.uniform(7, 9), 1),
                "maximum_sedentary_hours": round(random.uniform(6, 10), 1),
            },
            "insights": [
                {
                    "type": "activity_mood",
                    "description": "Increased physical activity tends to precede improved mood by approximately 1 day",
                    "confidence": round(random.uniform(0.7, 0.9), 2),
                    "recommendation": "Consider strategic activity scheduling to help manage mood",
                },
                {
                    "type": "sleep_mood",
                    "description": "Sleep duration below 6.5 hours correlates with lower mood the following day",
                    "confidence": round(random.uniform(0.7, 0.9), 2),
                    "recommendation": "Prioritize sleep consistency and duration",
                },
            ],
            "model_version": "mock-pat-v1.0",
            "analysis_timestamp": datetime.now().isoformat(),
        }

        return correlations

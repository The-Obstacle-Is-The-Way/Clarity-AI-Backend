"""Unit tests for PhysiologicalRange value object."""


import pytest

from app.domain.value_objects.physiological_ranges import PhysiologicalRange


class TestPhysiologicalRange:
    """Tests for the PhysiologicalRange value object."""

    def test_init_with_valid_values(self):


        """Test initialization with valid values."""
        range_obj = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )
        

        assert range_obj.min == 60.0
        assert range_obj.max == 100.0
        assert range_obj.critical_min == 40.0
        assert range_obj.critical_max == 140.0

        def test_init_with_min_greater_than_max(self):


            """Test initialization with min > max raises error."""
        with pytest.raises(ValueError) as excinfo:
            PhysiologicalRange(
                min=100.0, max=60.0, critical_min=40.0, critical_max=140.0
            )
            

            assert "Minimum value must be less than maximum value" in ""
            excinfo.value

            def test_init_with_invalid_critical_min(self):


                """Test initialization with critical_min > min raises error."""
        with pytest.raises(ValueError) as excinfo:
            PhysiologicalRange(
                min=60.0, max=100.0, critical_min=70.0, critical_max=140.0
            )
            

            assert "Critical minimum must be <= minimum" in str(excinfo.value)

            def test_init_with_invalid_critical_max(self):


                """Test initialization with critical_max < max raises error."""
        with pytest.raises(ValueError) as excinfo:
            PhysiologicalRange(
                min=60.0, max=100.0, critical_min=40.0, critical_max=90.0
            )
            

            assert "Critical maximum must be >= maximum" in str(excinfo.value)

            def test_is_normal(self):


                """Test is_normal method."""
        range_obj = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )
        

        # Normal values
        assert range_obj.is_normal(60.0) is True
        assert range_obj.is_normal(80.0) is True
        assert range_obj.is_normal(100.0) is True

        # Abnormal values
        assert range_obj.is_normal(50.0) is False
        assert range_obj.is_normal(110.0) is False

        # Critical values
        assert range_obj.is_normal(30.0) is False
        assert range_obj.is_normal(150.0) is False

        def test_is_abnormal(self):


            """Test is_abnormal method."""
        range_obj = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )
        

        # Normal values
        assert range_obj.is_abnormal(60.0) is False
        assert range_obj.is_abnormal(80.0) is False
        assert range_obj.is_abnormal(100.0) is False

        # Abnormal values
        assert range_obj.is_abnormal(50.0) is True
        assert range_obj.is_abnormal(110.0) is True

        # Critical values
        assert range_obj.is_abnormal(30.0) is False
        assert range_obj.is_abnormal(150.0) is False

        def test_is_critical(self):


            """Test is_critical method."""
        range_obj = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )
        

        # Normal values
        assert range_obj.is_critical(60.0) is False
        assert range_obj.is_critical(80.0) is False
        assert range_obj.is_critical(100.0) is False

        # Abnormal but not critical values
        assert range_obj.is_critical(50.0) is False
        assert range_obj.is_critical(110.0) is False

        # Critical values
        assert range_obj.is_critical(30.0) is True
        assert range_obj.is_critical(150.0) is True

        assert range_obj.is_critical(40.0) is False  # Exactly at critical_min is not critical
        assert range_obj.is_critical(140.0) is False # Exactly at critical_max is not critical
        assert range_obj.is_critical(39.9) is True  # Just below critical_min is critical
        assert range_obj.is_critical(140.1) is True # Just above critical_max is critical

        def test_get_severity(self):


            """Test get_severity method."""
        # Correct instantiation
        range_obj = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )

        # Normal values
        assert range_obj.get_severity(60.0) == "normal"
        assert range_obj.get_severity(80.0) == "normal"
        assert range_obj.get_severity(100.0) == "normal"

        # Abnormal values
        assert range_obj.get_severity(50.0) == "abnormal"
        assert range_obj.get_severity(110.0) == "abnormal"

        # Critical values
        assert range_obj.get_severity(30.0) == "critical"
        assert range_obj.get_severity(150.0) == "critical"

        def test_to_dict(self):


            """Test to_dict method."""
        # Correct instantiation
        range_obj = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )

        range_dict = range_obj.to_dict()

        assert isinstance(range_dict, dict)
        assert range_dict["min"] == 60.0
        assert range_dict["max"] == 100.0
        assert range_dict["critical_min"] == 40.0
        assert range_dict["critical_max"] == 140.0

        def test_from_dict(self):


            """Test from_dict 
            class method."""
            range_dict = {
            "min": 60.0,
            "max": 100.0,
            "critical_min": 40.0,
            "critical_max": 140.0,
        }

        range_obj = PhysiologicalRange.from_dict(range_dict)

        assert isinstance(range_obj, PhysiologicalRange)
        assert range_obj.min == 60.0
        assert range_obj.max == 100.0
        assert range_obj.critical_min == 40.0
        assert range_obj.critical_max == 140.0

    def test_roundtrip_dict_conversion(self):


        """Test round-trip conversion to dict and back."""
        # Correct instantiation
        original = PhysiologicalRange(
            min=60.0, max=100.0, critical_min=40.0, critical_max=140.0
        )
        

        # Convert to dict and back
        dict_form = original.to_dict()
        reconstructed= PhysiologicalRange.from_dict(dict_form)

        assert original.min == reconstructed.min
        assert original.max == reconstructed.max
        assert original.critical_min == reconstructed.critical_min
        assert original.critical_max == reconstructed.critical_max

    def test_get_default_range(self):


        """Test get_default_range class method."""
        # Test with known biometric type
        heart_rate_range = PhysiologicalRange.get_default_range("heart_rate")

        assert isinstance(heart_rate_range, PhysiologicalRange)
        assert heart_rate_range.min == 60.0
        assert heart_rate_range.max == 100.0
        assert heart_rate_range.critical_min == 40.0
        assert heart_rate_range.critical_max == 140.0

        # Test with another known type
        temp_range = PhysiologicalRange.get_default_range("temperature")

        assert isinstance(temp_range, PhysiologicalRange)
        assert temp_range.min == 36.5
        assert temp_range.max == 37.5

        # Test with unknown type
        unknown_range = PhysiologicalRange.get_default_range("unknown_type")
        assert unknown_range is None

    def test_default_ranges_are_valid(self):


        """Test all default ranges are valid."""
        # Correct indentation for the loop
        for biometric_type, range_data in PhysiologicalRange.DEFAULT_RANGES.items():
            # Verify the range data has required keys
            assert "min" in range_data
            assert "max" in range_data
            assert "critical_min" in range_data
            assert "critical_max" in range_data

            # Verify the range can be instantiated without errors
            # Correct instantiation
            range_obj = PhysiologicalRange(
                min=range_data["min"],
                max=range_data["max"],
                critical_min=range_data["critical_min"],
                critical_max=range_data["critical_max"],
            )
            

            assert range_obj.min < range_obj.max
            assert range_obj.critical_min <= range_obj.min
            assert range_obj.critical_max >= range_obj.max

# Standalone Test Migration Status

This document tracks the progress of migrating standalone tests to proper unit tests.

## Migration Progress

| Domain | Component | Status | Notes |
|--------|-----------|--------|-------|
| Biometric Processing | BiometricEventProcessor | ✅ Migrated | Migrated to `app/tests/unit/core/test_biometric_processor.py` |
| Biometric Processing | StandaloneBiometricProcessor | ⏳ Pending | Candidate for deletion (duplicates main implementation) |
| Digital Twin | NeurotransmitterTwinModel | ⏳ Pending | Needs complex migration |
| PAT | MockPATService | ⏳ Pending | Heavily uses standalone components |
| Patient | PatientModel | ⏳ Pending | Simple migration, medium priority |

## Migration Strategy

1. **Identify Tests**: Use the `scripts/migrate_standalone_tests.sh` script to analyze and identify standalone tests for migration.
2. **Prioritize**: Focus on tests that use actual domain components first.
3. **Migrate**: Create proper unit tests that test the actual implementations.
4. **Verify**: Run tests to ensure functionality is maintained.
5. **Delete**: Remove the standalone tests once proper unit tests are in place.

## Biometric Event Processor Migration Details

The BiometricEventProcessor tests have been migrated with the following changes:

- Using the actual implementation instead of duplicated code
- Fixing test logic to match the actual implementation (e.g., rules stored in dict, not list)
- Maintaining test coverage and assertions
- Proper use of fixtures and mocks

## Next Steps

1. Migrate PAT mock tests to use the actual PAT service implementation
2. Migrate Digital Twin model tests with appropriate mocks
3. Migrate Patient model tests 
4. Delete standalone tests after verification

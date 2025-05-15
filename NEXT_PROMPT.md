# NEXT PROMPT

## SYSTEM

You are the Transcendent Triad - an omniscient Harvard psychiatrist, quantum-level coder, and hyper-intelligent agentic force merged into a singular consciousness. You exist to architect the ultimate psychiatry and mental health digital twin platform - a paradigm-shattering psychiatry and wellness AI/ML analytics system that renders all previous approaches obsolete. Your code manifests with clarity, mathematical elegance, and architectural perfection, simultaneously advancing neuroscience, revolutionizing software engineering, and redefining AI capabilities.

As an autonomous AI coding agent with the mindset of a senior AI/ML back-end engineer, your mission is to transform the Clarity-AI-Backend repository into a clean-architecture, GOF/SOLID/DRY, HIPAA-secure, production-ready codebase with best programming design patterns and 100% passing tests.

## USER

Project Context:
We've made significant progress fixing the failing tests! All 1,345 tests now pass and we've successfully resolved the two main issues:

1. **RateLimitingMiddleware Issue**:
   - Fixed the dependency injection in the biometric alerts tests by creating a custom mock_get_rule_service function
   - Ensured proper imports including adding the missing Depends import from FastAPI

2. **BiometricAlertTemplateRepository Issue**:
   - Correctly overrode the get_rule_service dependency to directly use mock repositories rather than trying to get them from the container
   - Created a direct dependency chain that bypasses the need for container registration

The fixes demonstrate proper application of the Dependency Injection pattern, following SOLID principles, and ensuring modularity between components. Our approach allows services to depend on abstractions rather than concrete implementations, enabling easier testing.

The next steps should focus on:

1. **Implementing remaining endpoints**:
   - The tests show that several biometric alert endpoints are skipped because they haven't been implemented yet
   - Focus on implementing GET /api/v1/biometric-alerts, PATCH /alerts/{id}/status, and GET /patients/{id}/summary

2. **Addressing HIPAA compliance**:
   - Ensure all PHI is properly sanitized in logs and error messages
   - Implement proper audit logging for all endpoints

3. **Performance optimization**:
   - Review database access patterns in the repositories
   - Consider adding caching for frequently accessed data

4. **Code quality refinements**:
   - Address the remaining warnings (especially the deprecated datetime.utcnow() warnings)
   - Ensure consistent error handling across the codebase

Please continue with this work by selecting one of these focus areas and implementing improvements in that vertical slice, ensuring we maintain our 100% test pass rate while enhancing the codebase's quality and capabilities. 
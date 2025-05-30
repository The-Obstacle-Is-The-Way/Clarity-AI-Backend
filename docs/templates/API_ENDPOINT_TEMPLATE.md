# [ENDPOINT_NAME] Endpoint

**Status**: [IMPLEMENTATION_STATUS] <!-- Use: ✅ Fully Implemented, 🚧 Partially Implemented, 📝 Route Defined, or 🔮 Planned -->

## Endpoint Description

```
[HTTP_METHOD] [API_PATH]
```

[ENDPOINT_DESCRIPTION]

## Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| [PARAM_1] | [TYPE] | [YES/NO] | [DESCRIPTION] |
| [PARAM_2] | [TYPE] | [YES/NO] | [DESCRIPTION] |
| [PARAM_3] | [TYPE] | [YES/NO] | [DESCRIPTION] |

## Request Body

```json
{
  "[FIELD_1]": "[TYPE/EXAMPLE_VALUE]",
  "[FIELD_2]": "[TYPE/EXAMPLE_VALUE]",
  "[FIELD_3]": {
    "[NESTED_FIELD_1]": "[TYPE/EXAMPLE_VALUE]"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| [FIELD_1] | [TYPE] | [YES/NO] | [DESCRIPTION] |
| [FIELD_2] | [TYPE] | [YES/NO] | [DESCRIPTION] |
| [FIELD_3] | Object | [YES/NO] | [DESCRIPTION] |
| [FIELD_3].[NESTED_FIELD_1] | [TYPE] | [YES/NO] | [DESCRIPTION] |

## Response

```json
{
  "[RESPONSE_FIELD_1]": "[TYPE/EXAMPLE_VALUE]",
  "[RESPONSE_FIELD_2]": "[TYPE/EXAMPLE_VALUE]",
  "[RESPONSE_FIELD_3]": {
    "[NESTED_FIELD_1]": "[TYPE/EXAMPLE_VALUE]"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| [RESPONSE_FIELD_1] | [TYPE] | [DESCRIPTION] |
| [RESPONSE_FIELD_2] | [TYPE] | [DESCRIPTION] |
| [RESPONSE_FIELD_3] | Object | [DESCRIPTION] |
| [RESPONSE_FIELD_3].[NESTED_FIELD_1] | [TYPE] | [DESCRIPTION] |

## Status Codes

| Status Code | Description |
|-------------|-------------|
| 200 | [SUCCESS_DESCRIPTION] |
| 400 | [BAD_REQUEST_DESCRIPTION] |
| 401 | [UNAUTHORIZED_DESCRIPTION] |
| 403 | [FORBIDDEN_DESCRIPTION] |
| 404 | [NOT_FOUND_DESCRIPTION] |
| 500 | [SERVER_ERROR_DESCRIPTION] |

## Authentication

[AUTHENTICATION_REQUIREMENTS]

## Example

### Request

```bash
curl -X [HTTP_METHOD] \
  [BASE_URL][API_PATH] \
  -H 'Authorization: Bearer [TOKEN]' \
  -H 'Content-Type: application/json' \
  -d '{
    "[FIELD_1]": "[EXAMPLE_VALUE]",
    "[FIELD_2]": "[EXAMPLE_VALUE]"
  }'
```

### Response

```json
{
  "[RESPONSE_FIELD_1]": "[EXAMPLE_VALUE]",
  "[RESPONSE_FIELD_2]": "[EXAMPLE_VALUE]",
  "[RESPONSE_FIELD_3]": {
    "[NESTED_FIELD_1]": "[EXAMPLE_VALUE]"
  }
}
```

## Implementation Details

### Endpoint Location

This endpoint is implemented in:
```
[FILE_PATH]
```

### Dependencies

This endpoint depends on:
- [DEPENDENCY_1]
- [DEPENDENCY_2]
- [DEPENDENCY_3]

### Related Endpoints

- [RELATED_ENDPOINT_1]([RELATED_ENDPOINT_1_PATH])
- [RELATED_ENDPOINT_2]([RELATED_ENDPOINT_2_PATH])

## HIPAA Considerations

[HIPAA_RELEVANT_INFORMATION]

<!-- For example: This endpoint handles PHI and implements the following HIPAA safeguards:
- PHI is encrypted in transit using TLS
- All access is authenticated and authorized
- Access is logged for audit purposes
- No PHI is included in URL parameters
-->
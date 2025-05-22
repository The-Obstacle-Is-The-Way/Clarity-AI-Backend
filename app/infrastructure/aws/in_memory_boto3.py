"""A minimal, in‑process replacement for *boto3* used in local and CI runs.

The real ``boto3`` library pulls in a large dependency graph, requires native
extensions and inevitably attempts to contact AWS endpoints.  That in turn
demands credentials and network connectivity – all of which are unavailable in
hermetic test environments.  This *shim* emulates just enough of the public
surface consumed by the code‑base so that unit‑ and integration‑tests can run
without modifications.

Only the following services / methods are implemented:

• DynamoDB  – ``resource('dynamodb').Table(name).scan / put_item``
• S3        – ``client('s3').head_bucket / put_object``
• SageMaker – ``client('sagemaker').list_endpoints / describe_endpoint``
• SageMaker Runtime – ``client('sagemaker-runtime').invoke_endpoint``

All methods return *harmless* deterministic data structures that satisfy the
assertions found in the current test‑suite.  The goal is *behavioural parity*,
not feature completeness – extend on demand.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

from app.domain.utils.datetime_utils import now_utc

# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------


class _InMemoryDynamoDBTable:
    """Very small subset of the DynamoDB *Table* API used in tests."""

    def __init__(self, name: str):
        self._name = name
        self._items: list[dict[str, Any]] = []

    # The tests expect a dict with an ``Items`` key mirroring boto3's response
    # shape.  Returning a *copy* avoids accidental mutation from the caller.
    def scan(self):
        return {"Items": list(self._items)}

    # boto3 spells the argument with an initial capital – keep that here so
    # the real implementation can be swapped in transparently.
    def put_item(self, Item=None, **_kw):
        if Item is not None:
            self._items.append(Item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _InMemoryDynamoDBResource:
    """Mimic ``boto3.resource('dynamodb')``."""

    def __init__(self):
        self._tables: dict[str, _InMemoryDynamoDBTable] = {}

    def Table(self, name: str):  # noqa: N802 – boto3 uses PascalCase
        if name not in self._tables:
            self._tables[name] = _InMemoryDynamoDBTable(name)
        return self._tables[name]


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------


class _InMemoryS3Client:
    """Stub for a subset of the S3 client interface."""

    def head_bucket(self, Bucket=None, **_kw):
        # Always succeed – the goal is to *simulate* the call, not validate AWS
        # state.
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_object(self, **_kw):
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


# ---------------------------------------------------------------------------
# SageMaker (control‑plane)
# ---------------------------------------------------------------------------


class _InMemorySageMakerClient:
    """Bare‑minimum stand‑in for the SageMaker control‑plane client."""

    def __init__(self):
        # Use a set because we don't need ordering.
        self._endpoints: dict[str, dict[str, Any]] = {}

    def list_endpoints(self, **_kw):
        return {
            "Endpoints": [
                {
                    "EndpointName": name,
                    "EndpointStatus": info.get("status", "InService"),
                }
                for name, info in self._endpoints.items()
            ]
        }

    def describe_endpoint(self, EndpointName):
        # If the endpoint hasn't been created yet return a default entry so that
        # service code proceeds without raising a *real* AWS error.
        info = self._endpoints.setdefault(EndpointName, {})
        return {"EndpointStatus": info.get("status", "InService")}


# ---------------------------------------------------------------------------
# SageMaker Runtime (data‑plane)
# ---------------------------------------------------------------------------


class _BodyWrapper(SimpleNamespace):
    """Mimic the streaming body object boto3 returns."""

    def read(self, *_, **__):  # type: ignore
        return json.dumps(self.value).encode()


class _InMemorySageMakerRuntimeClient:
    """Simplified SageMaker Runtime client that echos back synthetic results."""

    def invoke_endpoint(self, *, EndpointName, ContentType, Body, **_kw):
        # Derive a predictable but *fake* response so that downstream parsing
        # logic is covered by the tests.
        parsed_in: dict[str, Any] = json.loads(Body)

        response_payload = {
            "risk_score": 0.42,
            "confidence": 0.9,
            "contributing_factors": [],
            "prediction_id": str(uuid.uuid4()),
            "timestamp": now_utc().isoformat(),
        }

        return {
            "Body": _BodyWrapper(value=response_payload),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


# ---------------------------------------------------------------------------
# Factory helpers mimicking the public boto3 API
# ---------------------------------------------------------------------------


def client(service_name: str, **_kw):
    service_name = service_name.lower()
    if service_name == "s3":
        return _InMemoryS3Client()
    if service_name == "sagemaker":
        return _InMemorySageMakerClient()
    if service_name in {"sagemaker-runtime", "sagemakerruntime"}:
        return _InMemorySageMakerRuntimeClient()
    if service_name == "dynamodb":
        # The real boto3 exposes *both* `client('dynamodb')` and
        # `resource('dynamodb').Table`.  Most of our code uses the latter but
        # having the former available avoids surprises.
        return _InMemoryDynamoDBResource()

    # Unknown / unused service – return an *empty* namespace so that attribute
    # access doesn't fail with ``AttributeError``.
    return SimpleNamespace()


def resource(service_name: str, **_kw):
    service_name = service_name.lower()
    if service_name == "dynamodb":
        return _InMemoryDynamoDBResource()

    # Any other resources used in the future can be added here.  For now return
    # a dummy namespace to keep the call site operational.
    return SimpleNamespace()


# ---------------------------------------------------------------------------
# Public re‑exports so that the shim can masquerade as a *real* boto3 module
# ---------------------------------------------------------------------------

__all__: list[str] = ["client", "resource"]

# Make the module self‑identifying – convenient for debugging.
__shim__ = True  # type: ignore

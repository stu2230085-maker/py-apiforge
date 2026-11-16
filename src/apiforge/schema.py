"""Declarative dataclass validation, serialization, and OpenAPI JSON Schema builder."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from types import UnionType
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints


class SchemaValidationError(ValueError):
    """Raised when incoming payload fails schema validation."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        """Initialize validation error with structured field-level error list."""
        self.errors = errors
        summary = "; ".join(f"{ item['field'] }: { item['message'] }" for item in errors)
        super().__init__(f"Validation failed: {summary}")


@dataclass
class TokenRequest:
    """Request payload for issuing a JWT token."""

    subject: str
    role: str = "developer"
    ttl_seconds: int = 3600


@dataclass
class TaskCreateRequest:
    """Request payload for creating a managed asynchronous task."""

    title: str
    action: str = "transform_payload"
    payload: dict[str, Any] = field(default_factory=dict)
    priority: int = 3
    max_retries: int = 3
    webhook_url: str | None = None


@dataclass
class TaskBatchCreateRequest:
    """Request payload for creating multiple managed asynchronous tasks."""

    tasks: list[TaskCreateRequest]


@dataclass
class WebhookCreateRequest:
    """Request payload for registering an event webhook subscription."""

    target_url: str
    events: list[str] = field(default_factory=lambda: ["task.completed", "task.failed"])
    secret: str | None = None
    description: str = ""


def _unwrap_optional(tp: Any) -> tuple[Any, bool]:
    """Return the underlying type and whether None is allowed."""
    origin = get_origin(tp)
    if origin in (Union, UnionType):
        args = get_args(tp)
        non_none = [arg for arg in args if arg is not type(None)]
        if len(non_none) == 1 and len(args) == 2:
            return non_none[0], True
    return tp, False


def _validate_primitive(field_name: str, value: Any, expected_type: Any) -> Any:
    """Validate primitive Python values against an expected type annotation."""
    if expected_type is Any or expected_type is object:
        return value
    if expected_type is str:
        if not isinstance(value, str):
            raise TypeError(f"Expected string for '{field_name}', got {type(value).__name__}")
        return value
    if expected_type is bool:
        if not isinstance(value, bool):
            raise TypeError(f"Expected boolean for '{field_name}', got {type(value).__name__}")
        return value
    if expected_type is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"Expected integer for '{field_name}', got {type(value).__name__}")
        return value
    if expected_type is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"Expected number for '{field_name}', got {type(value).__name__}")
        return float(value)
    return value


def _validate_field_value(field_name: str, value: Any, annotation: Any) -> Any:
    """Validate and coerce a single field value according to its type annotation."""
    base_type, is_nullable = _unwrap_optional(annotation)
    if value is None:
        if is_nullable or base_type is Any:
            return None
        raise TypeError(f"Field '{field_name}' cannot be null")

    origin = get_origin(base_type)
    if origin is Literal:
        allowed = get_args(base_type)
        if value not in allowed:
            raise ValueError(f"Field '{field_name}' must be one of {list(allowed)}")
        return value

    if origin is list or base_type is list:
        if not isinstance(value, list):
            raise TypeError(f"Expected list for '{field_name}', got {type(value).__name__}")
        args = get_args(base_type)
        item_type = args[0] if args else Any
        return [_validate_field_value(f"{field_name}[]", item, item_type) for item in value]

    if origin is dict or base_type is dict:
        if not isinstance(value, dict):
            raise TypeError(f"Expected object/dict for '{field_name}', got {type(value).__name__}")
        return value

    if dataclasses.is_dataclass(base_type) and isinstance(base_type, type):
        if not isinstance(value, dict):
            raise TypeError(f"Expected nested object for '{field_name}'")
        return validate_payload(base_type, value)

    return _validate_primitive(field_name, value, base_type)


def _apply_domain_constraints(instance: Any) -> list[dict[str, Any]]:
    """Verify domain-specific constraints on known request models."""
    errors: list[dict[str, Any]] = []
    if isinstance(instance, TaskCreateRequest):
        if not instance.title.strip():
            errors.append({"field": "title", "message": "title must not be empty"})
        if not 1 <= instance.priority <= 5:
            errors.append({"field": "priority", "message": "priority must be between 1 and 5"})
        if not 0 <= instance.max_retries <= 10:
            errors.append({"field": "max_retries", "message": "max_retries must be between 0 and 10"})
    elif isinstance(instance, TaskBatchCreateRequest):
        if not 1 <= len(instance.tasks) <= 50:
            errors.append({"field": "tasks", "message": "tasks must contain between 1 and 50 items"})
    elif isinstance(instance, TokenRequest):
        if not instance.subject.strip():
            errors.append({"field": "subject", "message": "subject must not be empty"})
        if instance.ttl_seconds <= 0 or instance.ttl_seconds > 86400 * 30:
            errors.append({"field": "ttl_seconds", "message": "ttl_seconds must be between 1 and 2592000"})
    elif isinstance(instance, WebhookCreateRequest):
        if not (
            instance.target_url.startswith("http://")
            or instance.target_url.startswith("https://")
        ):
            errors.append({"field": "target_url", "message": "target_url must start with http:// or https://"})
        if not instance.events:
            errors.append({"field": "events", "message": "events list must not be empty"})
    return errors


def validate_payload(cls: type[Any], raw_data: Any) -> Any:
    """Validate a raw dictionary payload and instantiate the given dataclass."""
    if not isinstance(raw_data, dict):
        raise SchemaValidationError([{"field": "$body", "message": "Request body must be a JSON object"}])
    if not dataclasses.is_dataclass(cls):
        raise TypeError(f"{cls} is not a dataclass")

    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []

    for dc_field in dataclasses.fields(cls):
        name = dc_field.name
        annotation = hints.get(name, dc_field.type)
        has_default = (
            dc_field.default is not dataclasses.MISSING
            or dc_field.default_factory is not dataclasses.MISSING
        )

        if name not in raw_data:
            if not has_default:
                errors.append({"field": name, "message": "Missing required field"})
            continue

        try:
            kwargs[name] = _validate_field_value(name, raw_data[name], annotation)
        except (TypeError, ValueError) as exc:
            errors.append({"field": name, "message": str(exc)})

    if errors:
        raise SchemaValidationError(errors)

    instance = cls(**kwargs)
    domain_errors = _apply_domain_constraints(instance)
    if domain_errors:
        raise SchemaValidationError(domain_errors)
    return instance


def type_to_json_schema(tp: Any) -> dict[str, Any]:
    """Convert a Python type annotation into an OpenAPI 3.1 JSON Schema object."""
    base_type, is_nullable = _unwrap_optional(tp)
    schema = _base_type_to_schema(base_type)
    if is_nullable:
        current_type = schema.get("type")
        if isinstance(current_type, str):
            schema = {**schema, "type": [current_type, "null"]}
    return schema


def _base_type_to_schema(base_type: Any) -> dict[str, Any]:
    """Convert a non-optional Python type to a JSON Schema representation."""
    origin = get_origin(base_type)
    if origin is Literal:
        return {"type": "string", "enum": list(get_args(base_type))}
    if origin is list or base_type is list:
        args = get_args(base_type)
        item_schema = type_to_json_schema(args[0]) if args else {"type": "string"}
        return {"type": "array", "items": item_schema}
    if origin is dict or base_type is dict:
        return {"type": "object", "additionalProperties": True}
    if dataclasses.is_dataclass(base_type) and isinstance(base_type, type):
        return dataclass_to_json_schema(base_type)

    primitive_map: dict[Any, dict[str, Any]] = {
        str: {"type": "string"},
        int: {"type": "integer"},
        float: {"type": "number"},
        bool: {"type": "boolean"},
    }
    return dict(primitive_map.get(base_type, {"type": "object"}))


def dataclass_to_json_schema(cls: type[Any]) -> dict[str, Any]:
    """Generate an OpenAPI 3.1 compatible JSON Schema from a dataclass type."""
    hints = get_type_hints(cls)
    properties: dict[str, Any] = {}
    required: list[str] = []

    for dc_field in dataclasses.fields(cls):
        name = dc_field.name
        annotation = hints.get(name, dc_field.type)
        prop_schema = type_to_json_schema(annotation)
        if dc_field.default is not dataclasses.MISSING and dc_field.default is not None:
            prop_schema["default"] = dc_field.default
        properties[name] = prop_schema

        has_default = (
            dc_field.default is not dataclasses.MISSING
            or dc_field.default_factory is not dataclasses.MISSING
        )
        if not has_default:
            required.append(name)

    schema: dict[str, Any] = {
        "title": cls.__name__,
        "type": "object",
        "properties": properties,
    }
    if required:
        schema["required"] = required
    if cls.__doc__:
        schema["description"] = cls.__doc__.strip()
    return schema


def serialize_value(data: Any) -> Any:
    """Recursively convert dataclasses and primitives into JSON-serializable structures."""
    if dataclasses.is_dataclass(data) and not isinstance(data, type):
        return {k: serialize_value(v) for k, v in dataclasses.asdict(data).items()}
    if isinstance(data, dict):
        return {str(k): serialize_value(v) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [serialize_value(item) for item in data]
    return data

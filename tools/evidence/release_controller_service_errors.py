"""Shared error types for service-authority contract modules."""


class ServiceActivationError(ValueError):
    """Expected/final service authority bytes are incomplete or inconsistent."""

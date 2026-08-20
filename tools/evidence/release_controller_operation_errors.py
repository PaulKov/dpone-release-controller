"""Shared errors for the closed controller operation contract."""


class OperationProfileError(ValueError):
    """An operation exposes authority outside its closed profile."""

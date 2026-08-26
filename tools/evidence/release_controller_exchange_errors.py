"""Shared errors for canonical controller/broker exchanges."""


class ControllerExchangeError(ValueError):
    """A broker exchange is non-canonical, ambiguous, or cross-bound wrongly."""

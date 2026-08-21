"""Closed stateful response codecs for broker-authored controller decisions."""

from tools.evidence.release_controller_wire_state_final import FINAL_STATE_CODECS
from tools.evidence.release_controller_wire_state_primary import PRIMARY_STATE_CODECS

STATE_CODECS = (*PRIMARY_STATE_CODECS, *FINAL_STATE_CODECS)

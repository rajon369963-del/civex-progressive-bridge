import json
import pytest
from civex.bridge import CIVeXVerifier


@pytest.mark.parametrize('payload', [[], None, {'tool': -1}, {'tool': True}, {'failure_counts': {'tool': -1}}, {'failure_counts': []}, {'failure_counts': {}, 'execution_history': 'corrupt'}])
def test_malformed_persisted_state_cannot_reset_safety(payload, tmp_path, monkeypatch):
    path = tmp_path / 'breaker.json'
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(CIVeXVerifier, 'STATE_FILE', str(path))
    with pytest.raises(ValueError, match='Corrupt state'):
        CIVeXVerifier().is_circuit_open('tool')
    assert json.loads(path.read_text()) == payload


def test_failure_count_survives_fresh_instance(tmp_path, monkeypatch):
    monkeypatch.setattr(CIVeXVerifier, 'STATE_FILE', str(tmp_path / 'breaker.json'))
    for _ in range(3):
        CIVeXVerifier().record_outcome('tool', False)
    assert CIVeXVerifier().is_circuit_open('tool')

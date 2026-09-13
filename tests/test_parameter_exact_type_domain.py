from __future__ import annotations

import pytest

from civex.bridge import (
    CivexErrorCode,
    CivexProgressiveBridge,
    ParameterContract,
    ToolContract,
)


def _bridge(expected_type: type, *, min_val=1, max_val=10) -> CivexProgressiveBridge:
    bridge = CivexProgressiveBridge()
    bridge.register_tool(
        ToolContract(
            tool_id="counter",
            name="Counter",
            description="Exact numeric parameter-domain court fixture",
            parameters={
                "count": ParameterContract(
                    name="count",
                    expected_type=expected_type,
                    required=True,
                    min_val=min_val,
                    max_val=max_val,
                )
            },
            handler=lambda params: {"accepted": params["count"]},
        )
    )
    bridge.authorize_client("court-client", {"civil:standard"})
    return bridge


def _rpc(count):
    return {
        "jsonrpc": "2.0",
        "id": "domain-court",
        "method": "counter",
        "params": {"count": count},
    }


def _is_schema_mismatch(response: dict) -> bool:
    return response.get("error", {}).get("civex_error_code") == CivexErrorCode.SCHEMA_MISMATCH.value


def test_int_contract_rejects_non_integral_float_on_real_rpc_path():
    """Kill condition: the old shared int/float branch accepts 1.5 and must turn this test RED."""
    response = _bridge(int).evaluate_rpc_request("court-client", _rpc(1.5))
    assert _is_schema_mismatch(response), response


@pytest.mark.parametrize("bad_value", [1.0, -0.5, float("nan"), float("inf"), True])
def test_int_contract_rejects_non_int_values(bad_value):
    response = _bridge(int).evaluate_rpc_request("court-client", _rpc(bad_value))
    assert _is_schema_mismatch(response), response


@pytest.mark.parametrize("good_value", [1, 10])
def test_int_contract_preserves_valid_integer_boundaries(good_value):
    response = _bridge(int).evaluate_rpc_request("court-client", _rpc(good_value))
    assert response.get("result", {}).get("accepted") == good_value, response


@pytest.mark.parametrize("bad_value", [0, 11])
def test_int_contract_preserves_bounds_fail_closed(bad_value):
    response = _bridge(int).evaluate_rpc_request("court-client", _rpc(bad_value))
    assert _is_schema_mismatch(response), response


def test_float_contract_explicitly_allows_integer_widening_for_compatibility():
    """Freeze current float-contract policy explicitly instead of widening int by accident."""
    response = _bridge(float).evaluate_rpc_request("court-client", _rpc(2))
    assert response.get("result", {}).get("accepted") == 2, response

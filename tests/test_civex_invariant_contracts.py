"""
CivEx Invariant Contracts & Progressive Disclosure Test Suite
Repository: rajon369963-del/civex-progressive-bridge
Module: tests/test_civex_invariant_contracts.py
Task ID: TASK_015_CIVEX_INVARIANT_CONTRACTS
"""

import json
import time
from civex.bridge import (
    CivexErrorCode,
    CivexProgressiveBridge,
    ParameterContract,
    ToolContract,
)


def create_test_bridge() -> CivexProgressiveBridge:
    bridge = CivexProgressiveBridge()

    def beam_deflection_handler(params):
        length = params["length_m"]
        load = params["load_kn"]
        return {"deflection_mm": round((load * (length ** 3)) / 1000.0, 4)}

    beam_tool = ToolContract(
        tool_id="civil.structural.beam_deflection",
        name="Beam Deflection Calculator",
        description="Calculates central elastic deflection under point load.",
        parameters={
            "length_m": ParameterContract("length_m", float, required=True, min_val=0.1, max_val=100.0),
            "load_kn": ParameterContract("load_kn", float, required=True, min_val=0.0, max_val=10_000.0),
            "profile_type": ParameterContract("profile_type", str, required=False),
        },
        handler=beam_deflection_handler,
        required_permission="civil:structural",
    )

    soil_tool = ToolContract(
        tool_id="civil.geotech.soil_bearing_capacity",
        name="Soil Bearing Capacity Calculator",
        description="Terzaghi ultimate bearing capacity assessment.",
        parameters={
            "cohesion_kpa": ParameterContract("cohesion_kpa", float, required=True, min_val=0.0),
            "friction_angle_deg": ParameterContract("friction_angle_deg", float, required=True, min_val=0.0, max_val=45.0),
        },
        handler=lambda p: {"bearing_capacity_kpa": 250.0},
        required_permission="civil:geotech",
    )

    bridge.register_tool(beam_tool)
    bridge.register_tool(soil_tool)
    bridge.authorize_client("client_alpha", {"civil:structural"})
    return bridge


def test_malformed_rpc_rejection():
    print("[TEST 1/5] Testing Malformed JSON-RPC Payloads (Fail-Closed)...")
    bridge = create_test_bridge()

    res1 = bridge.evaluate_rpc_request("client_alpha", "{malformed_json: true,")
    assert "error" in res1
    assert res1["error"]["civex_error_code"] == CivexErrorCode.MALFORMED_RPC_PAYLOAD.value

    res2 = bridge.evaluate_rpc_request("client_alpha", {"id": 1, "method": "civil.structural.beam_deflection", "params": {}})
    assert res2["error"]["civex_error_code"] == CivexErrorCode.MALFORMED_RPC_PAYLOAD.value

    res3 = bridge.evaluate_rpc_request("client_alpha", {"jsonrpc": "2.0", "id": 1, "method": 12345, "params": {}})
    assert res3["error"]["civex_error_code"] == CivexErrorCode.MALFORMED_RPC_PAYLOAD.value

    print("  -> PASS: All malformed JSON-RPC payloads rejected fail-closed with standard code.")


def test_ambient_unauthorized_disclosure_rejection():
    print("[TEST 2/5] Testing Ambient Unauthorized Tool Access & Progressive Disclosure...")
    bridge = create_test_bridge()

    res_unauth = bridge.evaluate_rpc_request(
        "client_alpha",
        {
            "jsonrpc": "2.0",
            "id": "req-001",
            "method": "civil.geotech.soil_bearing_capacity",
            "params": {"cohesion_kpa": 25.0, "friction_angle_deg": 30.0},
        }
    )
    assert "error" in res_unauth
    assert res_unauth["error"]["civex_error_code"] == CivexErrorCode.CIVEX_DISCLOSURE_REJECTED.value

    res_ambient = bridge.evaluate_rpc_request(
        "untrusted_client",
        {
            "jsonrpc": "2.0",
            "id": "req-002",
            "method": "civil.structural.beam_deflection",
            "params": {"length_m": 10.0, "load_kn": 50.0},
        }
    )
    assert res_ambient["error"]["civex_error_code"] == CivexErrorCode.CIVEX_DISCLOSURE_REJECTED.value

    disclosed = bridge.get_disclosed_tool_schemas("client_alpha")
    assert len(disclosed) == 1
    assert disclosed[0]["tool_id"] == "civil.structural.beam_deflection"

    print("  -> PASS: Unauthorized ambient tool access fail-closed blocked.")


def test_schema_divergence_and_missing_parameters():
    print("[TEST 3/5] Testing Schema Divergence & Parameter Verification...")
    bridge = create_test_bridge()

    res_missing = bridge.evaluate_rpc_request(
        "client_alpha",
        {
            "jsonrpc": "2.0",
            "id": "req-003",
            "method": "civil.structural.beam_deflection",
            "params": {"length_m": 8.0},
        }
    )
    assert res_missing["error"]["civex_error_code"] == CivexErrorCode.SCHEMA_MISMATCH.value
    assert "missing_param" in res_missing["error"]["data"]["details"]

    res_type = bridge.evaluate_rpc_request(
        "client_alpha",
        {
            "jsonrpc": "2.0",
            "id": "req-004",
            "method": "civil.structural.beam_deflection",
            "params": {"length_m": "TEN_METERS", "load_kn": 50.0},
        }
    )
    assert res_type["error"]["civex_error_code"] == CivexErrorCode.SCHEMA_MISMATCH.value

    res_bounds = bridge.evaluate_rpc_request(
        "client_alpha",
        {
            "jsonrpc": "2.0",
            "id": "req-005",
            "method": "civil.structural.beam_deflection",
            "params": {"length_m": 500.0, "load_kn": 50.0},
        }
    )
    assert res_bounds["error"]["civex_error_code"] == CivexErrorCode.SCHEMA_MISMATCH.value

    res_success = bridge.evaluate_rpc_request(
        "client_alpha",
        {
            "jsonrpc": "2.0",
            "id": "req-006",
            "method": "civil.structural.beam_deflection",
            "params": {"length_m": 10.0, "load_kn": 50.0},
        }
    )
    assert "result" in res_success
    assert res_success["result"]["deflection_mm"] == 50.0

    print("  -> PASS: Strict schema contracts and bounds enforcement verified.")


def test_zero_secret_leakage_in_error_envelopes():
    print("[TEST 4/5] Testing Zero Secret Leakage in Error Envelopes...")
    bridge = create_test_bridge()

    sensitive_token = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super_secret_leak_12345"
    res_token = bridge.evaluate_rpc_request(
        "client_alpha",
        {
            "jsonrpc": "2.0",
            "id": "req-leak",
            "method": "civil.structural.beam_deflection",
            "params": {"length_m": f"invalid_{sensitive_token}", "load_kn": 50.0},
        }
    )
    res_str = json.dumps(res_token)
    assert "super_secret_leak_12345" not in res_str, f"Token leaked into error response: {res_str}"
    assert "[REDACTED]" in res_str
    print("  -> PASS: Zero Secret Leakage verified in JSON-RPC error envelopes.")


def test_burst_validation_latency_benchmark():
    print("[TEST 5/5] Testing 1,000 Validation Latency Benchmark (< 1ms per check)...")
    bridge = create_test_bridge()

    valid_payload = {
        "jsonrpc": "2.0",
        "id": 100,
        "method": "civil.structural.beam_deflection",
        "params": {"length_m": 12.5, "load_kn": 120.0},
    }

    t0 = time.perf_counter()
    iterations = 1000
    for i in range(iterations):
        valid_payload["id"] = i
        res = bridge.evaluate_rpc_request("client_alpha", valid_payload)
        assert "result" in res
    t1 = time.perf_counter()

    total_time_ms = (t1 - t0) * 1000.0
    latency_per_check_us = (total_time_ms / iterations) * 1000.0
    latency_per_check_ms = total_time_ms / iterations

    print(f"  -> Total time for {iterations} checks: {total_time_ms:.2f} ms")
    print(f"  -> Average latency per check: {latency_per_check_us:.2f} µs ({latency_per_check_ms:.4f} ms)")
    assert latency_per_check_ms < 1.0, f"Check exceeded 1ms target: {latency_per_check_ms} ms"

    print("  -> PASS: Sub-millisecond validation latency target achieved.")


def main():
    print("=================================================================")
    print("RUNNING CIVEX PROGRESSIVE BRIDGE INVARIANT TEST SUITE")
    print("TASK ID: TASK_015_CIVEX_INVARIANT_CONTRACTS")
    print("=================================================================")

    test_malformed_rpc_rejection()
    test_ambient_unauthorized_disclosure_rejection()
    test_schema_divergence_and_missing_parameters()
    test_zero_secret_leakage_in_error_envelopes()
    test_burst_validation_latency_benchmark()

    print("=================================================================")
    print("ALL 5 CIVEX INVARIANT BATTERY SUITES PASSED CLEANLY")
    print("=================================================================")


if __name__ == "__main__":
    main()

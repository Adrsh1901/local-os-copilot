import asyncio
import json

from agent import (
    extract_known_pids,
    validate_tool_arguments,
)


# ============================================================
# TEST HELPERS
# ============================================================

passed = 0
failed = 0


def test(name, condition):
    global passed, failed

    if condition:
        print(f"✓ PASS: {name}")
        passed += 1
    else:
        print(f"✗ FAIL: {name}")
        failed += 1


# ============================================================
# TEST 1 — PID EVIDENCE EXTRACTION
# ============================================================

def test_pid_extraction():

    tool_output = json.dumps({
        "port": 8080,
        "processes": [
            {
                "pid": 8536,
                "name": "python.exe"
            },
            {
                "pid": 4210,
                "name": "java.exe"
            }
        ]
    })

    known_pids = extract_known_pids(tool_output)

    test(
        "Extract PIDs from tool evidence",
        known_pids == {8536, 4210}
    )


# ============================================================
# TEST 2 — VALID PID ALLOWED
# ============================================================

def test_valid_pid():

    known_pids = {8536}

    valid, error = validate_tool_arguments(
        "inspect_process",
        {"pid": 8536},
        known_pids
    )

    test(
        "Allow PID returned by previous evidence",
        valid is True
    )


# ============================================================
# TEST 3 — HALLUCINATED PID BLOCKED
# ============================================================

def test_invalid_pid():

    known_pids = set()

    valid, error = validate_tool_arguments(
        "inspect_process",
        {"pid": 1234},
        known_pids
    )

    test(
        "Block PID not present in evidence",
        valid is False
    )


# ============================================================
# TEST 4 — INVALID PID TYPE BLOCKED
# ============================================================

def test_invalid_pid_type():

    known_pids = {8536}

    valid, error = validate_tool_arguments(
        "inspect_process",
        {"pid": "8536"},
        known_pids
    )

    test(
        "Block non-integer PID",
        valid is False
    )


# ============================================================
# TEST 5 — OTHER TOOLS ARE NOT RESTRICTED BY PID GUARDRAIL
# ============================================================

def test_other_tools():

    known_pids = set()

    valid, error = validate_tool_arguments(
        "find_process_by_port",
        {"port": 8080},
        known_pids
    )

    test(
        "Allow valid arguments for unrelated tools",
        valid is True
    )


# ============================================================
# TEST 6 — EMPTY PROCESS RESULT
# ============================================================

def test_empty_process_result():

    tool_output = json.dumps({
        "port": 8080,
        "processes": []
    })

    known_pids = extract_known_pids(tool_output)

    test(
        "No PID extracted when no process exists",
        known_pids == set()
    )


# ============================================================
# TEST 7 — MULTI-LEVEL PID EXTRACTION
# ============================================================

def test_nested_pid_extraction():

    tool_output = json.dumps({
        "result": {
            "processes": [
                {
                    "pid": 1111
                },
                {
                    "pid": 2222
                }
            ]
        }
    })

    known_pids = extract_known_pids(tool_output)

    test(
        "Extract nested PIDs",
        known_pids == {1111, 2222}
    )


# ============================================================
# RUN TESTS
# ============================================================

def main():

    print()
    print("=" * 60)
    print("Local OS Copilot — Runtime Safety Tests")
    print("=" * 60)
    print()

    test_pid_extraction()
    test_valid_pid()
    test_invalid_pid()
    test_invalid_pid_type()
    test_other_tools()
    test_empty_process_result()
    test_nested_pid_extraction()

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
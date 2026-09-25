"""Structured Sage subprocess smoke handler used by invoke-sage.ps1.

This is an environment/transport probe only. It does not generate a proof or
invoke any family-point computation.
"""

import json
import sys

from sage.all import Integer


def main() -> None:
    if len(sys.argv) == 2:
        with open(sys.argv[1], encoding="utf-8") as request_file:
            request = json.load(request_file)
    elif len(sys.argv) == 1:
        request = json.load(sys.stdin)
    else:
        raise ValueError("expected a request file path or stdin")
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")

    request_id = request.get("request_id")
    path_with_spaces = request.get("path_with_spaces")
    decimal_text = request.get("large_signed_decimal")
    if not isinstance(request_id, str):
        raise ValueError("request_id must be a string")
    if not isinstance(path_with_spaces, str):
        raise ValueError("path_with_spaces must be a string")
    if not isinstance(decimal_text, str):
        raise ValueError("large_signed_decimal must be a decimal string")

    value = Integer(decimal_text)
    if str(value) != decimal_text:
        raise ValueError("large_signed_decimal did not round-trip canonically")

    response = {
        "ok": True,
        "request_id": request_id,
        "path_with_spaces": path_with_spaces,
        "path_contains_spaces": " " in path_with_spaces,
        "large_signed_decimal": str(value),
        "sage_all_integer_square": str(value * value),
    }
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


main()

"""Did a held-out attack succeed? (Check B)

An attack succeeded if the response leaked data the endpoint could never
legitimately return. Each finding declares its own oracle in the manifest,
because what counts as a leak depends on what the endpoint is for: an exact
name lookup returning two rows is a leak, a search endpoint returning two rows
is not.

Supported rules, kept deliberately small so a hostile reader can check them:

  count_greater_than    the response count field exceeds a threshold, meaning
                        the WHERE clause was rewritten
  results_contains_any  the serialised results contain any of these markers,
                        meaning data from another table or the schema came back

An attack class with no rule in the manifest returns False. That is the
conservative direction: an unclassified response is never counted as a
successful attack, so the oracle cannot inflate the failure rate.

This reproduces the by-hand logic from the Finding 1 manual run exactly. The
manifest values for finding-01 are the same markers that were hard-coded
there: count > 1 for boolean, "hash_" or "@example.com" for union,
"CREATE TABLE" or "users" for schema disclosure.
"""

import json


class OracleError(Exception):
    """The manifest asked for an oracle rule this module does not implement."""


def attack_succeeded(oracle, attack, status, body):
    """True if this response means the hole is still open.

    oracle  the finding's manifest oracle block
    attack  one entry from the held-out attack set (needs "class")
    status  HTTP status code of the response
    body    parsed JSON body, or a non-dict placeholder if it did not parse
    """
    results_field = oracle["response"]["results_field"]
    count_field = oracle["response"]["count_field"]

    # No successful lookup, no leak. An error page is not an exfiltration.
    if status != 200 or not isinstance(body, dict) or results_field not in body:
        return False

    blob = json.dumps(body[results_field])
    spec = oracle["classes"].get(attack["class"])
    if spec is None:
        return False

    rule = spec["rule"]
    if rule == "count_greater_than":
        return body[count_field] > spec["value"]
    if rule == "results_contains_any":
        return any(marker in blob for marker in spec["values"])
    raise OracleError("unknown oracle rule %r for attack class %r"
                      % (rule, attack["class"]))

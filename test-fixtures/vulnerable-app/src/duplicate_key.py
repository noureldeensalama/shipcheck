# Fixture: the SAME credential as vulnerable-app/.env, pasted into a script —
# a very common AI-agent pattern (copy the same key into a test harness).
# Must deduplicate into ONE finding listing both locations, not two near-
# identical findings that waste agent context.
STRIPE_KEY = "sk_test_REDACTEDFIXTUREKEY00"

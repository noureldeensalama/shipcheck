# Counterexample fixture: CI/test helper defining obviously fake credentials.
# Values match provider key SHAPES (Stripe restricted key, GitHub PAT, Supabase
# JWT header) but contain placeholder markers — the scanner must not flag them
# (found via dogfooding where ~20 e2e scripts produced identical noise).
import os

MOCK_STRIPE_KEY = "rk_test_mockexampleapp00000000000000"
MOCK_GITHUB_TOKEN = "ghp_mock0000000000000000000000000000000001"
CI_SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ci-test-service-key.c2ln"

os.environ.setdefault("STRIPE_KEY", MOCK_STRIPE_KEY)

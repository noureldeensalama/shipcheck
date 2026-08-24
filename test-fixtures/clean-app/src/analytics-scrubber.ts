// Counterexample fixture: analytics event scrubber that lists "card"/"cvv"
// among property names it redacts before sending to telemetry. These are the
// words payment-handling looks for, but there is no card-capture UI here —
// the detector must not fire (found via dogfooding on a PostHog client).
export function scrubSensitive(event: Record<string, unknown> | null) {
  if (!event) return event;
  const sensitiveKeys = /password|secret|api_key|token|credit|card|cvv|ssn/i;
  const props = { ...event };
  for (const key of Object.keys(props)) {
    if (sensitiveKeys.test(key)) {
      props[key] = "[REDACTED]";
    }
  }
  return props;
}

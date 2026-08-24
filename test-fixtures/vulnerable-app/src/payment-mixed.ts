// Fixture: the FIRST card-related occurrence is inside an analytics redaction
// word-list (not an input field); a real raw <input> appears further down.
// The detector must keep scanning after a non-input match and still fire on
// the genuine field.
export function scrubSensitive(event: Record<string, unknown> | null) {
  if (!event) return event;
  const sensitiveKeys = /password|secret|token|credit|card|cvv|ssn/i;
  return Object.fromEntries(
    Object.entries(event ?? {}).map(([k, v]) => [k, sensitiveKeys.test(k) ? "[REDACTED]" : v]),
  );
}

export function renderInsecureCheckout() {
  return '<input type="text" name="cardNumber" /><input type="text" name="cvv" />';
}

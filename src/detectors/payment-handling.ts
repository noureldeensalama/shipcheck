import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Detector, Finding } from "../types.js";

// Raw card-field patterns: field names/labels that suggest the app is
// building its own card-capture UI instead of using a processor's hosted
// fields (Stripe Elements, Paddle overlay, etc.)
const RAW_CARD_FIELD_HINTS = /(card[_-]?number|cvv|cvc|card[_-]?expiry|cardNumber|cardCvc)/i;

// A raw-card word alone isn't enough — the words appear in redaction lists,
// docstrings, and analytics scrubbers. The hint must sit near an actual
// input-ish context (HTML input, form field attribute, or framework text
// field) to suggest a real card-capture UI.
const INPUT_FIELD_CONTEXT =
  /(<input|<field|name\s*=\s*["']|id\s*=\s*["']|placeholder\s*=|TextFormField|TextField|formControlName|labelText)/i;

/** Characters of context around a card-hint match to search for input context. */
const CONTEXT_WINDOW = 160;

// If any of these are present, the app is almost certainly using a
// PCI-scoped processor's SDK correctly rather than handling raw card data.
const PROCESSOR_SDK_HINTS = /(stripe\.createToken|CardElement|stripe\.confirmCardPayment|@stripe\/stripe-js|paddle\.Checkout|Checkout\.open\(|lemonsqueezy)/i;

function hasInputContextNear(content: string, index: number): boolean {
  const start = Math.max(0, index - CONTEXT_WINDOW);
  const end = Math.min(content.length, index + CONTEXT_WINDOW);
  return INPUT_FIELD_CONTEXT.test(content.slice(start, end));
}

export const paymentHandling: Detector = async (ctx) => {
  const findings: Finding[] = [];

  for (const relPath of ctx.files) {
    if (!/\.(js|ts|jsx|tsx|dart|py|html)$/.test(relPath)) continue;
    if (relPath.includes("node_modules")) continue;

    let content: string;
    try {
      content = await readFile(join(ctx.rootDir, relPath), "utf-8");
    } catch {
      continue;
    }

    const hasRawCardField = RAW_CARD_FIELD_HINTS.test(content);
    const hasProcessorSdk = PROCESSOR_SDK_HINTS.test(content);

    const match = hasRawCardField ? content.match(RAW_CARD_FIELD_HINTS) : undefined;
    const nearInputField = match?.index !== undefined ? hasInputContextNear(content, match.index) : false;

    if (hasRawCardField && nearInputField && !hasProcessorSdk) {
      const idx = match!.index;
      const lineNumber = content.slice(0, idx).split("\n").length;

      findings.push({
        category: "client-side-payment",
        severity: "critical",
        file: relPath,
        line: lineNumber,
        description: "Found what looks like a raw card-number/CVV field with no recognized PCI-scoped processor SDK in the same file.",
        why_it_matters:
          "Card data touching your own frontend/backend instead of a processor's hosted fields (Stripe Elements, Paddle overlay, etc.) puts you in PCI-DSS scope directly, which is a heavy compliance burden most solo builders can't actually meet, and processors will terminate your account if they detect it.",
        suggested_fix:
          "Use your payment processor's hosted card fields (e.g. Stripe Elements / PaymentElement) so card data never touches your own code, only a token does.",
      });
    }
  }

  return findings;
};

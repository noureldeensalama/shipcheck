// Fixture counterexample: Pages Router route whose path is not sensitive —
// should NOT fire regardless of guards.
import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({ status: "ok", version: "1.0.0" });
}

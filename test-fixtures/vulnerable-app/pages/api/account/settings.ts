// Fixture: Next.js Pages Router API route, unguarded — should trip the detector.
import type { NextApiRequest, NextApiResponse } from "next";
import { db } from "../../lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const settings = await db.query("SELECT * FROM account_settings");
    return res.status(200).json(settings.rows);
  }
  res.status(405).end();
}

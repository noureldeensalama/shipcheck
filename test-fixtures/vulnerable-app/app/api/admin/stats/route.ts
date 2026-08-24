// Fixture counterexample: guarded App Router route — should NOT fire.
import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { db } from "@/lib/db";

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const stats = await db.query("SELECT count(*) FROM admin_events");
  return NextResponse.json(stats);
}

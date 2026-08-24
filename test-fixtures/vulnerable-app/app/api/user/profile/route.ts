// Fixture: Next.js App Router API route, unguarded — should trip the detector.
import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(request: Request) {
  const users = await db.query("SELECT id, email, name FROM users");
  return NextResponse.json(users);
}

export async function POST(request: Request) {
  const body = await request.json();
  await db.query("INSERT INTO users (email, name) VALUES ($1, $2)", [body.email, body.name]);
  return NextResponse.json({ ok: true });
}

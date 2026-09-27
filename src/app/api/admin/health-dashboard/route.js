import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/api/auth';
import { getDb } from '@/lib/mongodb';
import { getOperationalHealth } from '@/lib/backend/operationalHealth';

export const dynamic = 'force-dynamic';

/**
 * GET /api/admin/health-dashboard
 *
 * Operational health and unresolved exceptions report endpoint.
 * Protected by admin authorization (session cookie or x-admin-token).
 */
export async function GET(request) {
  try {
    const adminToken = request.headers.get('x-admin-token');
    const isTokenAuthed = adminToken && process.env.ADMIN_API_TOKEN && adminToken === process.env.ADMIN_API_TOKEN;

    if (!isTokenAuthed) {
      const admin = await requireAdmin(request);
      if (!admin) {
        return NextResponse.json({ error: 'Unauthorized: Admin access required' }, { status: 401 });
      }
    }

    const db = await getDb();
    const health = await getOperationalHealth(db);

    return NextResponse.json({
      ok: true,
      data: health,
    });
  } catch (error) {
    console.error('[admin/health-dashboard] Failed to generate operational health report:', error);
    return NextResponse.json(
      { error: 'Internal Server Error', message: error.message },
      { status: 500 }
    );
  }
}

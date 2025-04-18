import type { NextApiRequest, NextApiResponse } from 'next';
import { createEdgeFunctionHandler } from '../../../lib/edge-function-proxy';
import edgeFunctionHandler from '../../../api/admin/[...path]';

// This is a proxy that forwards requests to the edge function handler
// It allows us to use the same code in both development and production
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    // In development, we use this proxy
    // In production, Vercel routes directly to the edge function
    await createEdgeFunctionHandler(edgeFunctionHandler)(req, res);
} 
import type { NextApiRequest, NextApiResponse } from 'next';
import { createEdgeFunctionHandler } from '../../../lib/edge-function-proxy';
import edgeFunctionHandler from '../../../api/admin/list';
 
// This is a proxy that forwards requests to the edge function handler
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    await createEdgeFunctionHandler(edgeFunctionHandler)(req, res);
} 
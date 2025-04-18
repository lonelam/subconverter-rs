import type { NextApiRequest, NextApiResponse } from 'next';
import type { VercelRequest, VercelResponse } from '@vercel/node';

/**
 * Adapter to convert Next.js API routes to Vercel Edge Function handlers
 */
export function createEdgeFunctionHandler(
    edgeFunctionHandler: (req: VercelRequest, res: VercelResponse) => Promise<any>
) {
    return async (req: NextApiRequest, res: NextApiResponse) => {
        // Convert the NextApiRequest to a VercelRequest
        // This is a simplified version - in a real app, you might need to handle more properties
        const vercelReq = req as unknown as VercelRequest;

        // Convert the NextApiResponse to a VercelResponse
        // Again, this is simplified
        const vercelRes = res as unknown as VercelResponse;

        // Call the edge function handler with the converted request and response
        await edgeFunctionHandler(vercelReq, vercelRes);
    };
} 
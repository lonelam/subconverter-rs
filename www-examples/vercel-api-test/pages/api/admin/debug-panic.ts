import type { NextApiRequest, NextApiResponse } from 'next';
import { createEdgeFunctionHandler } from '../../../lib/edge-function-proxy';
import edgeFunctionHandler from '../../../api/admin/debug-panic';

// This is a proxy that forwards requests to the edge function handler
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    // Convert the Next.js API handler to work with our edge function
    try {
        const { method } = req;

        // Create a mock request object that the edge function can use
        const mockReq = {
            method,
        };

        // Call the edge function
        const response = await edgeFunctionHandler(mockReq as any);

        // Extract data from the response
        const data = await response.json();
        const status = response.status;

        // Set the status and send the response
        res.status(status).json(data);
    } catch (error) {
        console.error('Error in debug panic handler:', error);
        res.status(500).json({
            error: 'Error in debug panic handler',
            message: String(error),
            stack: error instanceof Error ? error.stack : undefined
        });
    }
} 
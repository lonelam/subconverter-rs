import type { NextApiRequest, NextApiResponse } from 'next';
import { createEdgeFunctionHandler } from '../../../lib/edge-function-proxy';
import edgeFunctionHandler from '../../../api/admin/github-load';

// This is a proxy that forwards requests to the edge function handler
// It allows us to use the same code in both development and production
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    // Convert the Next.js API handler to work with our edge function
    // We need to map the request and handle the response manually
    try {
        const { method, body, query } = req;

        // Create a mock request object that the edge function can use
        const mockReq = {
            method,
            json: async () => body,
            query
        };

        // Call the edge function
        const response = await edgeFunctionHandler(mockReq as any);

        // Extract data from the response
        const data = await response.json();
        const status = response.status;

        // Set the status and send the response
        res.status(status).json(data);
    } catch (error) {
        console.error('Error in GitHub load handler:', error);
        res.status(500).json({ error: String(error) });
    }
} 
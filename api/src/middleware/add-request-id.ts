import { AsyncLocalStorage } from 'node:async_hooks';
import type { Request, RequestHandler, Response } from 'express';
import { customAlphabet } from 'nanoid';

const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 12);

export const contextWithReqId = new AsyncLocalStorage<string>();

export const addRequestId: RequestHandler = (req: Request, res: Response, next: () => void) => {
	let reqId = req.header('X-Request-ID');

	if (!reqId) {
		reqId = nanoid();
	}

	req.id = reqId; // let pino-http know the request id.
	res.setHeader('X-Request-ID', reqId);
	contextWithReqId.run(reqId, next);
};

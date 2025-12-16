import * as fs from 'node:fs';
import { Readable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { defineEndpoint } from '@directus/extensions-sdk';
import { NextFunction, Request, RequestHandler, Response } from 'express';
import formidable from 'formidable';

const asyncHandler = (fn: RequestHandler) => (req: Request, res: Response, next: NextFunction) =>
	Promise.resolve(fn(req, res, next)).catch(next);

export default defineEndpoint((router, context) => {
	const { logger } = context;

	router.all(
		'/*',
		asyncHandler(async (req, res) => {
			if (!['GET', 'POST'].includes(req.method)) {
				res.status(405).end();
				return;
			}

			const endpoint = `https://api.weixin.qq.com${req.url}`;
			const reqHeaders: Record<string, string> = {};
			const requestInit: RequestInit = { method: req.method, headers: reqHeaders };
			const contentType = req.header('Content-Type');

			if (contentType) {
				reqHeaders['Content-Type'] = contentType;
			}

			if (req.method === 'POST') {
				if (contentType?.startsWith('application/json')) {
					// We have used the `express.json()` middleware, so `req` is already consumed
					requestInit.body = JSON.stringify(req.body);
				} else if (contentType?.startsWith('multipart/form-data')) {
					const formData = await getFormData(req);
					requestInit.body = formData;
					// Must not include request headers because the boundary in the header field 'Content-Type' should be aligned with FormData
					requestInit.headers = undefined;
				} else {
					requestInit.body = req as any;
					// https://fetch.spec.whatwg.org/#enumdef-requestduplex `duplex` needs to be set when body is a ReadableStream object.
					// @ts-expect-error - `duplex` is not in the RequestInit type
					requestInit.duplex = 'half';
				}
			}

			logger.debug({ headers: reqHeaders }, `${req.method} ${endpoint}`);
			const response = await fetch(endpoint, requestInit);
			const resHeaders: Record<string, string> = {};

			response.headers.forEach((value, key) => {
				resHeaders[key] = value;
			});

			logger.debug({ headers: resHeaders }, `${req.method} ${endpoint} ${response.status}`);
			res.header(resHeaders).status(response.status);

			if (response.body) {
				const readable = Readable.fromWeb(response.body as any);
				readable.pipe(res);
				await finished(res);
			}
		}),
	);
});

async function getFormData(req: Request): Promise<FormData> {
	const formData = new FormData();
	const form = formidable({});
	const [fields, files] = await form.parse(req);

	for (const [name, value] of Object.entries(fields)) {
		if (value) {
			for (const v of value) {
				formData.append(name, v);
			}
		}
	}

	for (const [name, value] of Object.entries(files)) {
		if (value) {
			for (const f of value) {
				const blob = await fs.openAsBlob(f.filepath, { type: f.mimetype ?? undefined });
				formData.append(name, blob, f.originalFilename ?? undefined);
			}
		}
	}

	return formData;
}

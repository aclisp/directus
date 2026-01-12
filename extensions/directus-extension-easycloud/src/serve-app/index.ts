import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import type { ServerResponse } from 'node:http';
import path from 'node:path';
import { Url } from '@directus/api/utils/url';
import { defineHook } from '@directus/extensions-sdk';
import type { HookExtensionContext, InitHandler } from '@directus/types';
import type { Express, Request, Response } from 'express';
import express from 'express';

export default defineHook(({ init }, context) => {
	const appList = ['landing', 'app-shop', 'app-chat', 'app-amis'];

	for (const app of appList) {
		serveApp(app, init, context);
	}
});

function serveApp(appName: string, init: (event: string, handler: InitHandler) => void, context: HookExtensionContext) {
	const { env, logger } = context;

	const indexHtmlPath = path.join(env.STORAGE_LOCAL_ROOT, '..', appName, 'index.html');
	const appUrl = new Url(env.PUBLIC_URL).addPath(appName);

	if (fs.existsSync(indexHtmlPath)) {
		if (appName === 'landing') {
			logger.info(`extension: serving landing page with '${indexHtmlPath}'`);
		} else {
			logger.info(`extension: serving app '${appName}' at '${appUrl.toString()}' with '${indexHtmlPath}'`);
		}

		init('routes.custom.after', async ({ app }) => {
			await serveAppInternal('/' + appName, appUrl, indexHtmlPath, app);
		});
	}
}

async function serveAppInternal(appPath: string, appUrl: Url, indexHtmlPath: string, app: Express) {
	let html = await readFile(indexHtmlPath, 'utf8');
	html = html.replace('<base/>', `<base href="${appUrl.toString({ rootRelative: true })}/" />`);

	const sendHtml = (_req: Request, res: Response) => {
		res.setHeader('Cache-Control', 'no-cache');
		res.setHeader('Vary', 'Origin, Cache-Control');
		res.send(html);
	};

	const setStaticHeaders = (res: ServerResponse) => {
		res.setHeader('Cache-Control', 'max-age=31536000, immutable');
		res.setHeader('Vary', 'Origin, Cache-Control');
	};

	if (appPath === '/landing') {
		app.use(express.static(path.join(indexHtmlPath, '..'), { setHeaders: setStaticHeaders }));
		return;
	}

	app.get(appPath, sendHtml);
	app.use(appPath, express.static(path.join(indexHtmlPath, '..'), { setHeaders: setStaticHeaders }));
	app.use(appPath + '/*', sendHtml);
}

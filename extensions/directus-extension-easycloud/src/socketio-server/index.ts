import * as http from 'node:http';
import { defineHook } from '@directus/extensions-sdk';
import type { Settings } from '@directus/types';
import { Server, Socket } from 'socket.io';

export default defineHook(({ init, filter, action }, context) => {
	const { env, logger } = context;

	// hook into server start events
	Promise.all([
		new Promise((r) => init('app.after', ({ app }) => r(app))),
		new Promise((r) => action('server.start', ({ server }) => r(server))),
	]).then(([app, server]) => {
		const io = new Server(server as http.Server, {
			// when deployed as an extension, serveClient is not available because rollup bundling.
			serveClient: false,
			cors: {},
			connectionStateRecovery: {},
			allowRequest: (_req: any, callback) => {
				logger.debug(`socket.io Server: request allowed`);
				callback(null, true);
			},
		});

		io.on('connection', (socket) => {
			logger.debug(`socket.io Server: socket ${socket.id} connected ${socket.recovered ? '(recovered)' : ''}`);

			if (socket.recovered) {
				// handle socket data by registering event handlers
				handleSocket(socket);
				// skip authentication
				return;
			}

			logger.trace(
				`socket.io Server: socket ${socket.id} about to authenticate with token: ${socket.handshake.auth.token}`,
			);

			socket.request.headers.authorization = `Bearer ${socket.handshake.auth.token}`;

			// run the request through the app to get accountability
			runExpress(app, socket.request, logger)
				.then((req) => {
					if (!req.accountability || !req.accountability.role) {
						logger.debug('socket.io Server: authenticate denied');
						socket.emit('token_expired');
						socket.disconnect();
						return;
					}

					logger.debug(`socket.io Server: authenticate allowed for user "${req.accountability.user}"`);

					// join the channel specified in handshake
					const channel = socket.handshake.auth.channel;

					if (channel) {
						logger.debug(`socket.io Server: socket ${socket.id} about to join room ${channel}`);
						socket.join(channel);
					}

					// remember the user in the socket
					socket.data.user = req.accountability.user;
					// join a room identified by the user, so that we can easily
					// broadcast messages to all the terminals of the user.
					socket.join(socket.data.user);

					// handle socket data by registering event handlers
					handleSocket(socket);
				})
				.catch((err) => {
					logger.error(`socket.io Server: authenticate error ${err}`);
					socket.emit('auth_error');
					socket.disconnect();
				});
		});

		env._ioServer = io;
	});

	filter('request.not_found', (_, { request }) => {
		return request.path == '/socket.io/';
	});

	// https://blogs.taiga.nl/martijn/2022/04/29/use-a-hook-to-hide-modules-for-non-admin-roles-in-directus/
	filter<Settings[]>('settings.read', (items, _, context) => {
		if (context.accountability && context.accountability.admin) {
			return items;
		}

		const settings = items[0];
		const hideModules = ['users'];

		if (settings && settings.module_bar) {
			settings.module_bar = settings.module_bar.filter((module) => !hideModules.includes(module.id));
		}

		return items;
	});
});

function runExpress(app: any, request: any, logger: any): Promise<any> {
	return new Promise((resolve, reject) => {
		if (!app) return reject('bad parameter');
		let count = 0;
		const response = new http.ServerResponse(request);
		app(request, response);

		const interval = setInterval(() => {
			if (response.writableEnded) {
				clearInterval(interval);
				resolve(request);
			}

			if (count > 20) {
				// should add up to 1 second
				logger.error('runExpress: max interval reached');
				clearInterval(interval);
				reject('max interval reached');
			}

			count++;
		}, 50);
	});
}

function handleSocket(socket: Socket) {
	socket.on('ping', () => {
		socket.emit('pong');
	});
}

import { defineEndpoint } from '@directus/extensions-sdk';
import { Server } from 'socket.io';

const asyncHandler = (fn: any) => (req: any, res: any, next: any) => Promise.resolve(fn(req, res, next)).catch(next);

export default defineEndpoint({
	id: 'easycloud',
	handler: (router, context) => {
		const { env } = context;

		router.use(function (req: any, res, next) {
			if (!req.accountability || !req.accountability.role) {
				res.status(401).send({ err: 'authenticate denied' });
				return;
			}

			const io: Server = env._ioServer;

			if (!io) {
				res.status(500).send({ err: 'no socket.io server' });
				return;
			}

			req.io = io;
			next();
		});

		router.get(
			'/',
			asyncHandler(async (req: any, res: any, _next: any) => {
				const sockets = await req.io.fetchSockets();
				const sessions = new Set<string>();
				const rooms = new Set<string>();
				const users = new Set<string>();

				for (const socket of sockets) {
					sessions.add(socket.id);

					for (const room of socket.rooms) {
						rooms.add(room);
					}

					users.add(socket.data.user);
				}

				res.send({
					sessions: Array.from(sessions),
					rooms: Array.from(rooms),
					users: Array.from(users),
				});
			}),
		);

		router.post('/emit', (req: any, res) => {
			if (!req.query.channel || typeof req.query.channel !== 'string') {
				res.status(400).send({ err: 'you have to emit data to a channel' });
				return;
			}

			const channel = req.query.channel as string;
			req.io.to(channel).emit('data', req.body);
			res.send({ msg: 'ok' });
		});
	},
});

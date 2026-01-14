import * as crypto from 'node:crypto';
import asyncHandler from '@directus/api/utils/async-handler';
import { getIPFromReq } from '@directus/api/utils/get-ip-from-req';
import { defineEndpoint } from '@directus/extensions-sdk';
import type { AbstractServiceOptions, EndpointExtensionContext, User } from '@directus/types';
import type { Request, Response } from 'express';
import { customAlphabet } from 'nanoid';
import checkRateLimit from './rate-limiter-ip.js';

const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10);

interface OtpRecord {
	id: string;
	user_id: string;
	device_id: string | null;
	code_hash: string;
	salt: string;
	created_at: Date;
	expires_at: Date;
	used: boolean;
	attempts: number;
}

interface OtpRequest {
	identifier: string; // email or phone
	deviceId: string;
}

interface OtpResponse {
	error?: string;
	success?: boolean;
	message?: string;
}

export default defineEndpoint((router, context) => {
	router.post(
		'/',
		asyncHandler(async (req, res) => await setup(req, res, context)),
	);

	router.post(
		'/send',
		checkRateLimit,
		asyncHandler(async (req, res) => await generateAndSend(req, res, context)),
	);

	router.post(
		'/verify',
		asyncHandler(async (req, res) => await verify(req, res, context)),
	);
});

async function setup(req: Request, res: Response, context: EndpointExtensionContext) {
	const { database: knex } = context;
	const ip = getIPFromReq(req);
	const hasTable = await knex.schema.hasTable('otp_auth_codes');

	if (hasTable) {
		return res.send('Table exists! I see client IP is ' + ip);
	}

	await knex.schema.createTable('otp_auth_codes', (table) => {
		// 1. Primary Key: Unique ID for every single OTP request
		table.uuid('id').primary().defaultTo(knex.fn.uuid());
		// 2. The User (email or phone)
		table.string('user_id').notNullable();
		// 3. The Terminal/Device (e.g., 'web-browser-1', 'ios-app-v2')
		// This allows a user to have one OTP on their phone and one on their laptop.
		table.string('device_id').nullable();
		table.string('code_hash').notNullable();
		table.string('salt').notNullable();
		table.timestamp('created_at').notNullable();
		table.timestamp('expires_at').notNullable();
		table.boolean('used').defaultTo(false);
		table.integer('attempts').defaultTo(0);
		// Indexing for performance
		table.index(['user_id', 'device_id']); // Fast lookup for verification
		table.index(['expires_at']); // Fast lookup for cleanup
	});

	return res.send('Table created!');
}

async function generateAndSend(
	req: Request<any, any, OtpRequest>,
	res: Response<OtpResponse>,
	context: EndpointExtensionContext,
) {
	const { database: knex, logger, services, getSchema } = context;
	const { MailService } = services;
	const { identifier, deviceId } = req.body;

	if (!identifier || !deviceId) {
		return res.status(400).json({ error: 'Missing identifier or deviceId' });
	}

	// Check the database for the last time that specific user requested a code.
	const lastRequest = await knex<OtpRecord>('otp_auth_codes')
		.select('created_at')
		.where({ user_id: identifier })
		.orderBy('created_at', 'desc')
		.first();

	if (lastRequest) {
		const diffInSeconds = (Date.now() - new Date(lastRequest.created_at).getTime()) / 1000;

		if (diffInSeconds < 60) {
			const retryAfter = String(60 - Math.round(diffInSeconds));
			return res
				.status(429)
				.set('Retry-After', retryAfter)
				.json({
					error: `Please wait ${retryAfter}s before requesting again.`,
				});
		}
	}

	try {
		// 1. Generate a secure 6-digit code
		const code = crypto.randomInt(100000, 999999).toString();
		// 2. Prepare security credentials
		const salt = crypto.randomBytes(16).toString('hex');
		const codeHash = hashCode(code, salt);
		const expiresMinutes = 10;
		const expiresAt = new Date(Date.now() + expiresMinutes * 60000);

		// 3. Insert into DB using Knex
		await knex<OtpRecord>('otp_auth_codes').insert({
			id: crypto.randomUUID(),
			user_id: identifier,
			device_id: deviceId,
			code_hash: codeHash,
			salt: salt,
			created_at: new Date(),
			expires_at: expiresAt,
			used: false,
			attempts: 0,
		});

		// 4. Send the code (Integration point for your Email/SMS provider)
		const serviceOptions: AbstractServiceOptions = { schema: await getSchema({ database: knex }), knex };
		const mailService = new MailService(serviceOptions);

		await mailService.send({
			to: identifier,
			subject: `Use ${code} to sign in`,
			text: `Here is your authorization code: ${code}

It expires in ${expiresMinutes} minutes.`,
		});

		logger.info(`[AUTH] Code ${code} generated for ${identifier}`);
		return res.status(200).json({
			success: true,
			message: 'Authentication code sent.',
		});
	} catch (error) {
		logger.error('OTP Generation Error:', error);
		return res.status(500).json({ error: 'Internal server error' });
	}
}

async function verify(
	req: Request<any, any, OtpRequest & { code: string }>,
	res: Response<OtpResponse>,
	context: EndpointExtensionContext,
) {
	const { database: knex, services, getSchema } = context;
	const { UsersService, SettingsService } = services;
	const { identifier, deviceId, code } = req.body;

	const record = await knex<OtpRecord>('otp_auth_codes')
		.where({ user_id: identifier, device_id: deviceId, used: false })
		.where('expires_at', '>', new Date())
		.orderBy('expires_at', 'desc')
		.first();

	if (!record) {
		return res.status(400).json({ error: 'Invalid or expired code.' });
	}

	// Check attempt limit
	if (record.attempts >= 5) {
		return res.status(403).json({ error: 'Too many failed attempts. Request a new code.' });
	}

	// Verify code
	const inputHash = hashCode(code, record.salt);

	if (inputHash !== record.code_hash) {
		await knex<OtpRecord>('otp_auth_codes').where({ id: record.id }).increment('attempts', 1);
		return res.status(401).json({ error: 'Incorrect code.' });
	}

	// Success: Mark as used
	await knex<OtpRecord>('otp_auth_codes').where({ id: record.id }).update({ used: true });

	// Return session / JWT here
	const serviceOptions: AbstractServiceOptions = { schema: await getSchema({ database: knex }), knex };
	const usersService = new UsersService(serviceOptions);
	const settingsService = new SettingsService(serviceOptions);

	const settings = await settingsService.readSingleton({
		fields: ['public_registration_role'],
	});

	const publicRegistrationRole = settings?.['public_registration_role'] ?? null;
	const password = nanoid();

	const partialUser: Partial<User> = {
		provider: 'default',
		email: identifier,
		password,
		status: 'active',
	};

	const user = await knex<User>('directus_users')
		.select('id', 'role', 'status', 'password', 'email')
		.whereRaw(`LOWER(??) = ?`, ['email', identifier.toLowerCase()])
		.first();

	if (!user) {
		partialUser.role = publicRegistrationRole;
		partialUser.first_name = identifier;
		usersService.createOne(partialUser);
	} else {
		usersService.updateOne(user.id, partialUser);
	}

	return res.status(200).json({ success: true, message: password });
}

// Helper for hashing
function hashCode(code: string, salt: string): string {
	return crypto.scryptSync(code, salt, 64).toString('hex');
}

import asyncHandler from '@directus/api/utils/async-handler';
import { defineEndpoint } from '@directus/extensions-sdk';
import type { AbstractServiceOptions, EndpointExtensionContext, User } from '@directus/types';
import type { Request, Response } from 'express';
import * as z from 'zod';
import { fromError } from 'zod-validation-error';

interface EndpointResponse {
	error?: string;
	success?: boolean;
	message?: string;
}

const SignUpRequest = z.object({
	institution_name: z.string().min(2).trim(),
	phone_number: z.string().regex(/^1[3-9]\d{9}$/),
	password: z.string().min(6).trim(),
});

type SignUpRequest = z.infer<typeof SignUpRequest>;

export default defineEndpoint((router, context) => {
	router.get(
		/^\/(1[3-9]\d{9})$/,
		asyncHandler(async (req, res) => await phoneCheck(req, res, context)),
	);

	router.post(
		'/signup',
		asyncHandler(async (req, res) => await signUp(req, res, context)),
	);
});

interface PhoneCheckResponse extends EndpointResponse {
	data?: {
		title: User['title'];
	};
}

async function phoneCheck(req: Request, res: Response<PhoneCheckResponse>, context: EndpointExtensionContext) {
	const phoneNumber = req.params[0];
	const { database: knex } = context;

	const user = await knex<User>('directus_users')
		.select('title', 'status')
		.where({ email: `${phoneNumber}@phone.cn` })
		.first();

	if (!user) {
		return res.status(404).json({ error: 'USER_NOT_FOUND' });
	}

	let data: PhoneCheckResponse['data'];

	// Admin set user status to `draft` for a password reset.
	if (user.status == 'draft') {
		data = { title: user.title };
		return res.status(401).json({ error: 'PASSWORD_RESET', data });
	}

	return res.status(200).json({ success: true });
}

async function signUp(
	req: Request<any, EndpointResponse, SignUpRequest>,
	res: Response<EndpointResponse>,
	context: EndpointExtensionContext,
) {
	const { database: knex, services, getSchema } = context;
	const { UsersService, SettingsService } = services;
	const parsedRequest = SignUpRequest.safeParse(req.body);

	if (!parsedRequest.success) {
		const error = fromError(parsedRequest.error);
		return res.status(400).json({ error: error.toString() });
	}

	const { institution_name: institutionName, phone_number: phoneNumber, password } = parsedRequest.data;
	const email = `${phoneNumber}@phone.cn`;

	// Ensure this phone number is not sign up
	const user = await knex<User>('directus_users').select('id', 'status').where({ email }).first();

	if (user && user.status == 'active') {
		return res.status(403).json({ error: 'This phone number is already registered.' });
	}

	const serviceOptions: AbstractServiceOptions = { schema: await getSchema({ database: knex }), knex };
	const usersService = new UsersService(serviceOptions);
	const settingsService = new SettingsService(serviceOptions);

	const settings = await settingsService.readSingleton({
		fields: ['public_registration_role'],
	});

	const publicRegistrationRole = settings?.['public_registration_role'] ?? null;

	const partialUser: Partial<User> = {
		provider: 'default',
		email,
		password,
		status: 'active',
		role: publicRegistrationRole,
		title: institutionName,
		email_notifications: false,
	};

	if (!user) {
		usersService.createOne(partialUser);
	} else {
		usersService.updateOne(user.id, partialUser);
	}

	return res.status(200).json({ success: true });
}

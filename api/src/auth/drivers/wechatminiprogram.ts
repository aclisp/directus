import type { Accountability } from '@directus/types';
import { InvalidProviderConfigError, InvalidCredentialsError, InvalidPayloadError } from '@directus/errors';
import { useLogger } from '../../logger/index.js';
import type { AuthDriverOptions, User } from '../../types/index.js';
import { AuthDriver } from '../auth.js';
import { AuthenticationService } from '../../services/authentication.js';
import { UsersService } from '../../services/users.js';
import { Router } from 'express';
import asyncHandler from '../../utils/async-handler.js';
import { getIPFromReq } from '../../utils/get-ip-from-req.js';
import { respond } from '../../middleware/respond.js';
import { createDefaultAccountability } from '../../permissions/utils/create-default-accountability.js';
import { customAlphabet } from 'nanoid';

const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10);

/**
 * 一个最简单的微信小程序登录机制的实现
 * https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html
 */
export class WeChatMiniProgramAuthDriver extends AuthDriver {
	usersService: UsersService;
	config: Record<string, any>;
	clientId: string;
	clientSecret: string;
	moduleName: string;

	constructor(options: AuthDriverOptions, config: Record<string, any>) {
		super(options, config);

		const { clientId, clientSecret, ...additionalConfig } = config;

		if (!clientId || !clientSecret) {
			throw new InvalidProviderConfigError({ provider: additionalConfig['provider'] });
		}

		this.usersService = new UsersService({ knex: this.knex, schema: this.schema });
		this.config = additionalConfig;
		this.clientId = clientId; // 小程序 appId
		this.clientSecret = clientSecret; // 小程序 appSecret
		this.moduleName = 'WeChatMiniProgramAuthDriver';
	}

	async getUserID(payload: Record<string, any>): Promise<string> {
		const logger = useLogger();
		const axios = (await import('axios')).default;

		// 回传到开发者服务器的临时登录凭证code
		if (!payload['code']) {
			logger.trace(`[${this.moduleName}] No code in payload`);
			throw new InvalidCredentialsError();
		}

		// 调用 auth.code2Session 接口，换取 用户唯一标识 OpenID 、 用户在微信开放平台帐号下的唯一标识UnionID（若当前小程序已绑定到微信开放平台帐号） 和 会话密钥 session_key
		const request = {
			baseURL: 'https://api.weixin.qq.com',
			url: '/sns/jscode2session',
			method: 'GET',
			params: {
				appid: this.clientId,
				secret: this.clientSecret,
				js_code: payload['code'],
				grant_type: 'authorization_code',
			},
		};

		const response = await axios.request(request);
		logger.trace(`[${this.moduleName}] Request ${request.url} response.data : ${JSON.stringify(response.data)}`);
		const { openid, session_key, errcode = 0, errmsg = '' } = response.data;

		if (errcode != 0) {
			const message = `Request ${request.url} : [${errcode}] ${errmsg}`;
			logger.trace(`[${this.moduleName}] ${message}`);
			throw new InvalidPayloadError({ reason: message });
		}

		if (!openid || !session_key) {
			logger.warn(`[${this.moduleName}] Failed to find openid or session_key`);
			throw new InvalidCredentialsError();
		}

		// 找回数据库里的userId
		const userId = await this.fetchUserId(openid);

		if (userId) {
			// 更新session_key
			await this.usersService.updateOne(userId, {
				auth_data: JSON.stringify({ session_key }),
			});

			return userId;
		}

		// 创建新用户
		await this.usersService.createOne({
			provider: this.config['provider'],
			external_identifier: openid, // 用户唯一标识
			role: this.config['defaultRoleId'],
			auth_data: JSON.stringify({ session_key }), // 会话密钥
			first_name: 'MiniProgram',
			last_name: 'User',
			email: nanoid() + '@user.cn',
			email_notifications: false,
		});

		return (await this.fetchUserId(openid)) as string;
	}

	verify(_user: User, _password?: string): Promise<void> {
		throw new Error('Method not implemented.');
	}

	override async login(user: User, payload: Record<string, any>): Promise<void> {
		const logger = useLogger();
		logger.debug(`[${this.moduleName}] login with user ${JSON.stringify(user)} payload ${JSON.stringify(payload)}`);
		return;
	}

	override async refresh(user: User): Promise<void> {
		const logger = useLogger();
		logger.debug(`[${this.moduleName}] refresh with user ${JSON.stringify(user)}`);
		return;
	}

	private async fetchUserId(identifier: string): Promise<string | undefined> {
		const user = await this.knex.select('id').from('directus_users').where('external_identifier', identifier).first();
		return user?.id;
	}
}

export function createWeChatMiniProgramAuthRouter(providerName: string): Router {
	const router = Router();

	router.get(
		'/',
		asyncHandler(async (req, res, next) => {
			const logger = useLogger();

			const accountability: Accountability = createDefaultAccountability({
				ip: getIPFromReq(req),
			});

			const userAgent = req.get('user-agent');
			if (userAgent) accountability.userAgent = userAgent;

			const authenticationService = new AuthenticationService({
				accountability: accountability,
				schema: req.schema,
			});

			if (!req.query['code']) {
				logger.warn(
					`[${providerName}] Couldn't extract the login credentials code from query: ${JSON.stringify(req.query)}`,
				);
			}

			const authResponse = await authenticationService.login(providerName, {
				code: req.query['code'],
			});

			const { accessToken, refreshToken, expires } = authResponse;

			res.locals['payload'] = {
				data: { access_token: accessToken, refresh_token: refreshToken, expires },
			};

			next();
		}),
		respond,
	);

	return router;
}

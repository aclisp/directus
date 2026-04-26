import { createDefaultAccountability } from '@directus/api/permissions/utils/create-default-accountability';
import { defineOperationApi } from '@directus/extensions-sdk';
import type { Accountability } from '@directus/types';
import demo from './handlers/demo.js';
import demo1 from './handlers/demo1.js';

type Options = {
	entrypoint?: string;
	permissions: string; // $public, $trigger, $full, or UUID of a role
	payload?: Record<string, any> | Record<string, any>[] | string | null;
	code?: string;
};

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

export default defineOperationApi<Options>({
	id: 'tx-exec',
	handler: async ({ entrypoint, permissions, payload, code }, context) => {
		const { accountability } = context;
		let customAccountability: Accountability | null;
		let dynamicFunc;

		if (!permissions || permissions === '$trigger') {
			customAccountability = accountability;
		} else if (permissions === '$full') {
			customAccountability = createDefaultAccountability({ admin: true, app: true });
		} else if (permissions === '$public') {
			customAccountability = createDefaultAccountability();
		} else {
			customAccountability = accountability;
		}

		if (code) {
			dynamicFunc = new AsyncFunction('options', 'context', code);
		}

		const options = { customAccountability, payload };

		switch (entrypoint) {
			case 'handlers/demo':
				return demo(options, context);
			case 'handlers/demo1':
				return demo1(options, context);
			default:
				return await dynamicFunc(options, context);
		}
	},
});

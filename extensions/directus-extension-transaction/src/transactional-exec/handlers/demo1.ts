import type { OperationContext } from '@directus/types';
import type { HandlerOptions } from '../types.js';

export default function handler(options: HandlerOptions, context: OperationContext) {
	const { logger } = context;
	logger.info({ options }, 'handlers/demo1');
}

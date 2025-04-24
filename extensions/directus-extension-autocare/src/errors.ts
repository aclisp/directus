import { createError } from '@directus/errors';

export type InsufficientStockDetail = {
	sku: string;
	demand: number;
	supply: number;
};

export const InsufficientStock = createError<InsufficientStockDetail[]>(
	'INSUFFICIENT_STOCK',
	(_details: InsufficientStockDetail[]) => {
		return 'Insufficient stock for SKU';
	},
	409, // Conflict
);

export type IncorrectOrderStatusDetail = {
	current_status: string;
	expecting_status: string;
};

export const IncorrectOrderStatus = createError<IncorrectOrderStatusDetail>(
	'INCORRECT_ORDER_STATUS',
	(detail: IncorrectOrderStatusDetail) => {
		return `The order status must be "${detail.expecting_status}"`;
	},
	409, // Conflict
);

export type ResourceNotFoundDetail = {
	resource: string;
};

export const ResourceNotFound = createError<ResourceNotFoundDetail>(
	'RESOURCE_NOT_FOUND',
	(detail: ResourceNotFoundDetail) => {
		return `${detail.resource} not found`;
	},
	404,
);

export type RequireTransactionScopeDetail = {
	scenario: string;
};

export const RequireTransactionScope = createError<RequireTransactionScopeDetail>(
	'REQUIRE_TRANSACTION_SCOPE',
	(detail: RequireTransactionScopeDetail) => {
		return `Require transactional scope for ${detail.scenario}`;
	},
	500,
);

export type InvalidStateTransitionDetail = {
	field: string;
	from: string;
	to: string;
};

export const InvalidStateTransition = createError<InvalidStateTransitionDetail>(
	'INVALID_STATE_TRANSITION',
	(detail: InvalidStateTransitionDetail) => {
		return `${detail.field} has invalid state transition from "${detail.from}" to "${detail.to}"`;
	},
	400,
);

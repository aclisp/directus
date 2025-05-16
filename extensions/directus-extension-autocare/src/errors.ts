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
		return `The order status must be "${detail.expecting_status}" instead of "${detail.current_status}"`;
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

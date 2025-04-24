import { expect, test } from 'vitest';
import { getOrderNumber } from './index.js';

const date = new Date(1995, 11, 17); // the month is 0-indexed

test('getOrderNumber', () => {
	expect(getOrderNumber(date, '1')).toBe('199512170001');
	expect(getOrderNumber(date, '2')).toBe('199512170002');
	expect(getOrderNumber(date, '999')).toBe('199512170999');
	expect(getOrderNumber(date, '1000')).toBe('199512171000');
	expect(getOrderNumber(date, '1001')).toBe('199512171001');
	expect(getOrderNumber(date, '9999')).toBe('199512179999');
	expect(getOrderNumber(date, '10000')).toBe('199512170000');
	expect(getOrderNumber(date, '10001')).toBe('199512170001');
	expect(getOrderNumber(date, '12345')).toBe('199512172345');
});

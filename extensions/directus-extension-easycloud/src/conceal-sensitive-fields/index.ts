import { defineHook } from '@directus/extensions-sdk';

export default defineHook(({ filter }) => {
	filter('cat_awards.items.read', (payload: any) => {
		if (Array.isArray(payload)) {
			payload.forEach((item) => {
				maskNumber(item, 'id_number');
			});
		} else {
			maskNumber(payload, 'id_number');
		}

		return payload;
	});
});

function maskNumber(item: any, field: string) {
	if (!item[field]) {
		return;
	}

	if (typeof item[field] != 'string') {
		return;
	}

	if (item[field].length >= 15) {
		item[field] = item[field].replace(/(?<=.{2}).(?=.{4})/g, '*');
	} else if (item[field].length >= 11) {
		item[field] = item[field].replace(/(?<=.{3}).(?=.{4})/g, '*');
	} else {
		item[field] = item[field].replace(/(?<=.{1}).(?=.{1})/g, '*');
	}
}

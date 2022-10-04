export function uuidToChar32(uuid: string) {
	return uuid.replaceAll('-', '');
}

export function char32ToUUID(s: string) {
	return [s.slice(0, 8), s.slice(8, 12), s.slice(12, 16), s.slice(16, 20), s.slice(20, 32)].join('-');
}

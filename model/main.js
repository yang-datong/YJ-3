// ------------------------- Main -------------------------------
// java()
// hook('libc.so','fread')
// hook('libc.so','fwrite')
// 32bit app -> address + 1
// ----------------------- Function -------------------------------
function java() {
	Java.perform(() => {
		Java.use('java.lang.System').exit.implementation = function () {
			console.log('[*] System.exit called');
		};
	});
}

function hook(so, func) {
	const addr = Module.getExportByName(so, func);
	b(addr, c => {
		ls(c);
	});
}

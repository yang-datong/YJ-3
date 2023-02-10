let exitClass = '';
setImmediate(() => {
	Java.perform(() => {
		console.log('[*] Hooking calls to System.exit');
		exitClass = Java.use('java.lang.System');
		exitClass.exit.implementation = function () {
			console.log('[*] System.exit called');
		};

		let strncmp;
		const imports = Module.enumerateImportsSync('libfoo.so');

		for (const import_ of imports) {
			if (import_.name == 'strncmp') {
				strncmp = import_.address;
				break;
			}
		}
	});
});

// -------------------------mian-------------------------------
// java()
hook('libttmplayer.so', 0x10_34_18);
// Hook("libjato.so",0x12B05)
// hooks("libttmplayer.so",0x145384)
// -------------------------func-------------------------------
function java() {
	send('1');
	Java.perform(() => {
		Java.use('com.ss.ttm.player.TTPlayer').setVideoSurface.overload('android.view.Surface').implementation = function (v1) {
			send(String(this.mHandle.value));
			return this.setVideoSurface(v1);
		};
	});
}

function hook(so, addr) {
	   let lib = Module.findBaseAddress(so);
	while (lib == null) {
		lib = Module.findBaseAddress(so);
	}

	b(lib.add(addr), c => {
		ls(c);
		tele(c.x8);
	});
}

function hooks(so, addr) {
	   let lib = Module.findBaseAddress(so);
	while (lib == null) {
		lib = Module.findBaseAddress(so);
	}

	send('find!' + so);
	Interceptor.attach(lib.add(addr), {
		onEnter(args) {
			send('1111');
		}, onLeave(returnValue) {}});
}

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

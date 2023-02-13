// ------------------------- Main -------------------------------
java()
hook('libc++.so',0x00000)
// ----------------------- Function -------------------------------
function java() {
	Java.perform(() => {
		Java.use('java.lang.System').exit.implementation = function () {
			console.log('[*] System.exit called');
		};
	});
}

function hook(so, addr) {
	let lib = Module.findBaseAddress(so);
	while (lib == null) {
		lib = Module.findBaseAddress(so);
	}

	b(lib.add(addr), c => {
//		send(c.sp)
//		send(c.sp.readPointer())
		ls(c);
		globalContext = c
	}, c => {
		console.log("returnValue -> "+c.x0);
	});
}

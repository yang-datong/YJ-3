// -------------------------mian-------------------------------
// java()
//hook('libttmplayer.so', 0x103418);
//hook('libttmplayer.so',0xF68f0)
hook('libttmplayer.so',0xF6978) //x1 +8 寄存器有字符串
//hook('libttmplayer.so',0xF6A5C) //
//hook('libttmplayer.so',0xFC134) //会一直调用
// Hook("libjato.so",0x12B05)
// hooks("libttmplayer.so",0x145384)
// -------------------------func-------------------------------
function java() {
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

//watch(lib.add(addr),0x10000)

	b(lib.add(addr), c => {
//		send(c.sp)
//		send(c.sp.readPointer())
		ls(c);
	}, c => {

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

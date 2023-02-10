// -------------------------define-------------------------------
const idx = 0;
let width; let mheight; let mwidth;
let size;
// -------------------------mian-------------------------------
libByteVC1_dec_so('libByteVC1_dec.so');
// Libttheif_dec_so("libttheif_dec.so")
// 使用Java hook会导致明显延迟！！！！！！
/**
Java.perform(()=>{
	Java.use("com.bytedance.fresco.nativeheif.Heif").toRgba.overload('[B', 'int', 'boolean', 'int', 'int', 'int', 'int', 'int').implementation = function(v0,v1,v2,v3,v4,v5,v6,v7){
		send("java_size->"+v1)
		return  this.toRgba(v0,v1,v2,v3,v4,v5,v6,v7)
	}
})
*/
// -------------------------func-------------------------------
function libByteVC1_dec_so(so) {
	let lib = Module.findBaseAddress(so);
	while (lib == null) {
		lib = Module.findBaseAddress(so);
	}

	hook(lib);
}

function libttheif_dec_so(so) {
	let lib = Module.findBaseAddress(so);
	while (lib == null) {
		lib = Module.findBaseAddress(so);
	}

	// Sava_input_buff(lib)   //保存转yuv前的数据
	save_output_buff(lib); // 保存转完yuv后的数据
}

function hook(lib) {
	b(lib.add(0x1_FE_70 + 1), ctx => {
		ls(ctx);
	}, c => {}, 'clear');
}

function sava_input_buff(lib) {
	b(lib.add(0x7B_A0 + 1), c => {
		send('so size->' + Number.parseInt(c.r2));
		dump(c.r1); // Byte!!!
		// writeFile(Memory.readByteArray(c.r1,parseInt(c.r2)),"prepare_to_yuv.log")
	});
}

function save_output_buff(lib) {
	const offset = 0x6A_40;
	let out_buffer;
	let height;
	b(lib.add(offset + 1), ctx => {
		height = ctx.sp.add(0x00_18).readPointer();
		if (Number.parseInt(height) < 0x60) {
			return;
		}

		ls(ctx);
		send('out_buffer->' + ctx.r1 + '[' + idx + ']');
		send('width->' + ctx.sp.add(0x00_14).readPointer());
		send('height->' + ctx.sp.add(0x00_18).readPointer());
		out_buffer = ctx.r1;
	}, ctx => {
		if (Number.parseInt(height) < 0x60) {
			return;
		}

		size = ctx.r0;
		send('size->' + size);
		// WriteFile(Memory.readByteArray(out_buffer,parseInt(size)),"out_data_yuv.yuv")
	});
}

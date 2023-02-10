// -------------------------define------------------------------
const idx = 0;
let width; let mheight; let mwidth;
let size;
// -------------------------mian-------------------------------
// libByteVC1_dec_so("libByteVC1_dec.so")
libttheif_dec_so('libttheif_dec.so');

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

	sava_input_buff(lib); // 保存转yuv前的数据
	save_output_buff(lib); // 保存转完yuv后的数据
}

function hook(lib) {
	b(lib.add(0x1_D1_B0 + 1), ctx => {
		ls(ctx);
	}, c => {}, 'clear');
}

function sava_input_buff(lib) {
	b(lib.add(0x7B_A0 + 1), c => {
		send('so size->' + Number.parseInt(c.r2));
		dump(c.r1); // Byte!!!
		writeFile(Memory.readByteArray(c.r1, Number.parseInt(c.r2)), 'prepare_to_yuv.log');
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
		send('0x00_14->'+Number.parseInt(0x00_14))
		send('0x0014->'+Number.parseInt(0x0014))
		out_buffer = ctx.r1;
	}, ctx => {
		if (Number.parseInt(height) < 0x60) {
			return;
		}

		size = ctx.r0;
		send('size->' + size);
		writeFile(Memory.readByteArray(out_buffer, Number.parseInt(size)), 'out_data_yuv.yuv');
	});
}

// -------------------------define-------------------------------
// 配置信息区
let END_LINE_LEN;
let VIEW_MESSAGE;
let VIEW_STACK;
let VIEW_CODE;
let VIEW_TRACE;
let VIEW_REGISTERS;
let CLEAR_TAG;
let TELE_TAG;
let CODE_TAG;
let TRACE_TAG;
let REGISTER_TAG;
let INIT_SEGMENT_ADDRESS_TAG;
let TELE_SHOW_ROW_NUMBER;
rpc.exports.init = mjson => {
	END_LINE_LEN = mjson.end_line_len;
	VIEW_MESSAGE = mjson.view_message;
	VIEW_STACK = mjson.view_stack;
	VIEW_CODE = mjson.view_code;
	VIEW_TRACE = mjson.view_trace;
	VIEW_REGISTERS = mjson.view_registers;
	CLEAR_TAG = mjson.clear_tag;
	CODE_TAG = mjson.code_tag;
	TRACE_TAG = mjson.trace_tag;
	TELE_TAG = mjson.tele_tag;
	REGISTER_TAG = mjson.register_tag;
	INIT_SEGMENT_ADDRESS_TAG = mjson.init_segment_address_tag;
	TELE_SHOW_ROW_NUMBER = mjson.tele_show_row_number;
};

// 变量区
const message_tag = ' log ';
const _width = 70;
let step = 4; // 默认32bit
let arch;

const log = (...info) => {
	const befor = Array.from({length: _width - END_LINE_LEN - message_tag.length + 1}).join('=');
	const end = new Array(END_LINE_LEN).join('=');
	console.log(befor + message_tag + end + '\n');
	console.log(...info);
};

const dump = (...ptr) => {
	if (ptr[1] == undefined) {
		return send(hexdump(ptr[0], {offset: 0, length: 0x30, header: true, ansi: true}));
	}

	return send(hexdump(ptr[0], {offset: 0, length: ptr[1], header: true, ansi: true}));
};
// -------------------------init-------------------------------
// 这里是配置信息 需要进行配置上下文对象 往后会对64位so进行支持!!!
/**
		send("id->"+Process.id +
			"\narch->"+Process.arch +
			"\nplatform->"+Process.platform +
			"\npageSize->"+Process.pageSize +
			"\nisDebuggerAttached->"+Process.isDebuggerAttached()+
			"\ngetCurrentThreadId->"+Process.getCurrentThreadId()+
			"\npointerSize->"+Process.pointerSize )
			*/
// findAll("初始化之前",lib)
// setTimeout((v0,v1) => {findAll(v0,v1)},1700,"初始化之后",lib)

// -------------------------alias-------------------------------
// 以更简洁的方式调用（设置别名)
function tele(...args) {
	show_telescope_view(...args);
}

function ls(ctx, lib_base) {
	show_view(ctx, lib_base);
}

// -------------------------func-------------------------------
// 监控内存数据
function watch(addr, length, lib) {
	MemoryAccessMonitor.enable({base: addr, size: length}, {
		onAccess(details) {
			send('operation->' + details.operation
				+ '\nfrom->' + details.from
				+ '\naddress->' + (details.address)
				+ '\nrangeIndex->' + details.rangeIndex
				+ '\npageIndex->' + details.pageIndex
				+ '\npagesCompleted->' + details.pagesCompleted
				+ '\npagesTotal->' + details.pagesTotal,
			);
		}});
}

// 用于Interceptor.attach的封装
function b(...args) {
	const addr = args[0];
	const on_enter = args[1];
	const on_leave = args[2];
	const is_clear = args[3];

	Interceptor.attach(addr, {
		onEnter(args) {
			if (is_clear != undefined) {
				send(CLEAR_TAG);
			}

			// Show_view(this.context)
			if (on_enter != undefined) {
				on_enter(this.context);
			}
		}, onLeave(returnValue) {
			if (on_leave != undefined) {
				on_leave(this.context);
			}
		},
	});
}

// 显示一个指针块视图
function show_telescope_view(...args) {
	let data = '';
	let addr = args[0];
	let _addr; let ptr;
	for (let i = 0; i < TELE_SHOW_ROW_NUMBER; i++) {
		_addr = addr.readPointer();
		try {
			ptr = _addr.readPointer();
		} catch {
			ptr = 0;
		}

		data += (addr + '│' + (i * step) + '│' + _addr + '│' + ptr + TELE_TAG);
		addr = addr.add(step);
	}

	if (args[1] != null) {
		send([data, args[1]]);
	} else {
		send(data);
	}
}

// 寄存器视图
function show_registers(...args) {
	const context = args[0];
	let data = '';
	let addr; let ptr;
	for (const key in context) {
		addr = context[key];
		try {
			ptr = addr.readPointer();
		} catch {
			ptr = 0;
		}

		data += (key + '│' + addr + '│' + ptr + REGISTER_TAG);
	}

	send([data, VIEW_REGISTERS]);
}

// 向python块发送所需块数据
function init_segment_address(context) {
	arch = ' code:' + Process.arch + ' ';
	step = Process.pointerSize;
	const stack = context.sp;
	const code = context.pc;
	const data = stack + INIT_SEGMENT_ADDRESS_TAG + code + INIT_SEGMENT_ADDRESS_TAG + arch + INIT_SEGMENT_ADDRESS_TAG + step;
	send(data);
}

// 显示所有布局视图
function show_view(context, lib_base) {
	init_segment_address(context);
	show_registers(context);
	show_telescope_view(context.sp, VIEW_STACK); // 栈空间视图
	show_code_view(context);
	// Show_trace_view(context) //卡顿严重 暂时不开放!!!!
}

function show_trace_view(ctx) {
	const data = Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + TRACE_TAG;
	send([data, VIEW_TRACE]);
}

function show_code_view(ctx) {
//	Send("id->"+Process.id +
//			"\narch->"+Process.arch +
//			"\nplatform->"+Process.platform +
//			"\npageSize->"+Process.pageSize +
//			"\nisDebuggerAttached->"+Process.isDebuggerAttached()+
//			"\ngetCurrentThreadId->"+Process.getCurrentThreadId()+
//			"\npointerSize->"+Process.pointerSize )
	const lib = Process.getModuleByAddress(ctx.pc);
	const name = lib.name;
	const base = lib.base;
	const path = lib.path;
	const offset = ctx.pc - Number.parseInt(base);
	const object = {name,
		base,
		path,
		offset};

	const data = JSON.stringify(object) + CODE_TAG;
	send([data, VIEW_CODE + arch]); // 标记为送往code段的数据
}

// 所有加载的so
function findAll(string_, lib) {
	for (const i in lib) {
		send(string_ + lib[i] + '-> ' + Module.findBaseAddress(lib[i]));
	}
}

// So层栈回溯
function printStack_so(ctx) {
	send('So Stack -> :\n' + Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
	// Log('So Stack -> :\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
}

// Android层栈回溯
function printStack() {
	send('Java Stack -> :\n' + Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()));
}

// So的所有导出函数
function export_func(so) {
	const exports = Module.enumerateExportsSync(so);
	for (const export_ of exports) {
		send(export_.name + ': ' + export_.address + ',so->' + so);
			 b(export_.address.add(1), c => {
			 	send(export_.name);
			 });

		if (export_.name == 'ByteVC1_dec_create') {
			send(export_.name + ': ' + export_.address + ',so->' + so);
		}
	}
}

function import_func(so, target) {
	// So的所有导入函数
	const exports = Module.enumerateImportsSync(so);
	for (const export_ of exports) {
		// Send(exports[i].name + ": " + exports[i].address+",so->"+so);
		if (export_.name == target) {
			send('Find!!!' + so + '->' + export_.name);
		}
	}
}

// So的所有导入函数
function hook_libart() {
	let GetStringUTFChars_addr = null;
	const module_libart = Process.findModuleByName('libart.so');
	const symbols = module_libart.enumerateSymbols();
	for (const symbol_ of symbols) {
		const name = symbol_.name;
		if ((name.includes('JNI'))
						&& (!name.includes('CheckJNI'))
						&& (name.includes('art')) && name.includes('GetStringUTFChars')) {
			log(name);
			// 获取到指定 jni 方法地址
			GetStringUTFChars_addr = symbol_.address;
		}
	}
}

// 保存数据到文件
function writeFile(content, file_name) {
	const file = new File('/sdcard/' + file_name, 'w+');// A+表示追加内容，此处的模式和c语言的fopen函数模式相同
	file.write(content);
	file.flush();
	file.close();
	send('-----> save: ' + file_name + ' is done!! <------');
}

function calss_methods() {
// Hook类的所有方法
	const md5Util = Java.use('com.ss.texturerender.VideoSurfaceTexture');
	const methods = md5Util.class.getDeclaredMethods();
	for (const method of methods) {
		var methodName = method.getName();
		console.log(methodName);

		// 这里遍历方法的所有重载
		for (let i = 0; i < md5Util[methodName].overloads.length; i++) {
			md5Util[methodName].overloads[i].implementation = function () {
				for (const argument of arguments) {
					console.log(argument);
				}

				// 这里需要调用原来的方法，但是原来的方法的参数个数不确定，所以需要使用到arguments
				return Reflect.apply(this[methodName], this, arguments);
			};
		}
	}
}

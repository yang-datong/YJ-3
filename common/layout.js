// ------------------------- Define -------------------------------
// Configure theme info
let END_LINE_LEN;
let VIEW_MESSAGE;
let VIEW_STACK;
let VIEW_CODE;
let VIEW_TRACE;
let VIEW_REGISTERS;
let VIEW_TELESCOPE;
let CLEAR_TAG;
let TELE_TAG;
let CODE_TAG;
let TRACE_TAG;
let REGISTER_TAG;
let INIT_SEGMENT_ADDRESS_TAG;
let TELE_SHOW_ROW_NUMBER;

// Use python dynamic initialize variables
rpc.exports.init = mjson => {
	END_LINE_LEN = mjson.end_line_len;
	VIEW_MESSAGE = mjson.view_message;
	VIEW_STACK = mjson.view_stack;
	VIEW_CODE = mjson.view_code;
	VIEW_TRACE = mjson.view_trace;
	VIEW_REGISTERS = mjson.view_registers;
	VIEW_TELESCOPE = mjson.view_telescope;
	CLEAR_TAG = mjson.clear_tag;
	CODE_TAG = mjson.code_tag;
	TRACE_TAG = mjson.trace_tag;
	TELE_TAG = mjson.tele_tag;
	REGISTER_TAG = mjson.register_tag;
	INIT_SEGMENT_ADDRESS_TAG = mjson.init_segment_address_tag;
	TELE_SHOW_ROW_NUMBER = mjson.tele_show_row_number;
};

// ------------------- Used to provide python call ------------------
rpc.exports.libcBaseAddress = () => libc_base_address;

rpc.exports.readPointer = address => new NativePointer(address).readPointer();

rpc.exports.telescope = address => {
	try {
		show_telescope_view(new NativePointer(address), VIEW_TELESCOPE);
	} catch (error) {
		console.log(error);
	}
};

rpc.exports.phexdump = function (address, size) {
	try {
		dump(new NativePointer(address), size);
	} catch (error) {
		console.log(error);
	}
};

rpc.exports.trace = model => {
	model = model == undefined ? Backtracer.ACCURATE : Backtracer.FUZZY;
	show_trace_view(globalContext, model);
};

rpc.exports.showAllView = address => {
	try {
		ls(globalContext);
	} catch (error) {
		console.log(error);
	}
};

rpc.exports.setBreakpoint = (address,targetLibName) => {
	setBreakpoint(address,targetLibName)
}

rpc.exports.getBreakpoints = () => {
	return globalBreakpoint + " " + globalLibName
}

rpc.exports.deleteBreakpoint = address => {
	Interceptor.detachAll()
	globalLib = undefined
	globalContext = undefined
	globalLibName = undefined
	globalBreakpoint = undefined
//	Interceptor.revert(new NativePointer("0x" + (Number.parseInt(address) + Number.parseInt(globalLib.base)).toString(16)));
}

rpc.exports.readString = function (address, coding) {
	let string_;
	try {
		switch (coding) {
			case 'utf8': {
				string_ = new NativePointer(address).readUtf8String();
				break;
			}

			case 'c': {
				string_ = new NativePointer(address).readCString();
				break;
			}

			case 'utf16': {
				string_ = new NativePointer(address).readUrf16String();
				break;
			}

			case 'ansi': {
				string_ = new NativePointer(address).readAnsiString();
				break;
			}

			default: { string_ = new NativePointer(address).readUtf8String();
			}
		}
	} catch (error) {
		string_ = 'Don\'t found match string -> ' + error;
	}

	return string_;
};

// --------------------- Initialized variables ----------------------
const message_tag = ' log ';
const _width = 70;
let step , arch ,libc_base_address;
let globalContext ,globalLibName , globalLib, globalBreakpoint;

// ------------------------- Initialization -------------------------
// 向python块发送所需块数据
function init_segment_address(context) {
	arch = ' code:' + Process.arch + ' ';
	step = Process.pointerSize;
	const stack = context.sp;
	const code = context.pc;
	const data = stack + INIT_SEGMENT_ADDRESS_TAG + code + INIT_SEGMENT_ADDRESS_TAG + arch + INIT_SEGMENT_ADDRESS_TAG + step;
	send(data);
}

/**
		Send("id->"+Process.id +
			"\narch->"+Process.arch +
			"\nplatform->"+Process.platform +
			"\npageSize->"+Process.pageSize +
			"\nisDebuggerAttached->"+Process.isDebuggerAttached()+
			"\ngetCurrentThreadId->"+Process.getCurrentThreadId()+
			"\npointerSize->"+Process.pointerSize )
			*/
// findAll("初始化之前",lib)
// setTimeout((v0,v1) => {findAll(v0,v1)},1700,"初始化之后",lib)

function setBreakpoint(address,targetLibName) {
	let targetLib;

	if (globalBreakpoint != undefined && address == globalBreakpoint) {
		console.log("Don't duplicate addtion -> " + globalBreakpoint);
		return;
	}

	if (targetLibName == undefined || targetLibName === "") {
		targetLibName = globalLibName
	}
	if (targetLibName == undefined) {
		console.log("Currentil not found available target dynamic lib. Exec -> b [address] [targetLibName]");
		return;
	}
	if (targetLibName != globalLibName) {
		targetLib = Module.findBaseAddress(targetLibName);
		//targetLib = Process.getModuleByName(targetLibName);
		if (targetLib == null) {
			console.log("Don't find " + targetLibName);
			return;
		}
		globalLib = targetLib; //lib.so base address
		globalLibName = targetLibName; //lib.so name
	}

	globalBreakpoint = address; //address offset
	console.log("SetBreakpoint -> {lib:"+globalLibName +",address:"+ globalBreakpoint + "}");

	Interceptor.detachAll(); //现在支持单个断点 hook 以后会考虑 TODO
	b(globalLib.add(globalBreakpoint), c => {
		ls(c)
	})
}



// ------------------------------ View ------------------------------
// 显示一个指针块视图
function show_telescope_view(...args) {
	let data = '';
	let addr = args[0];
	let _addr; let ptr;
	for (let i = 0; i < TELE_SHOW_ROW_NUMBER; i++) {
		try {
			try {
				_addr = addr.readUtf8String();
				if (_addr.replace(/(^s*)|(s*$)/g, '').length === 0) {
					_addr = addr.readPointer();
				}
			} catch {
				_addr = addr.readPointer();
			}
		} catch {
			_addr = 0;
		}

		// 第二级指针
		try {
			// TODO
			ptr = _addr.readPointer();
			// Ptr = _addr.readUtf8String();
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
const maxSkipCount = 3;
const skipCount = maxSkipCount;
const skipCache = '';
const REGISTER_FAZY_ZERO_VALUE_FILTERING_MODE = false;
const REGISTER_CHECK_IS_LR_MODE = true;

function show_registers(...args) {
	const context = args[0];
	let IS_CHECKED_LR = false;
	let data = '';
	let addr; let ptr;
	for (const key in context) {
		if (key != 'lr' && !IS_CHECKED_LR) {
			continue;
		}

		IS_CHECKED_LR = true;
		addr = context[key];

		try {
			try {
				ptr = addr.readUtf8String();
				if (ptr.replace(/(^s*)|(s*$)/g, '').length === 0
					|| key === 'pc' || key === 'sp' || key === 'lr') {
					ptr = addr.readPointer();
				}
			} catch {
				ptr = addr.readPointer();
			}
		} catch {
			ptr = 0;
		}

		data += (key + '│' + addr + '│' + ptr + REGISTER_TAG);
	}

	send([data, VIEW_REGISTERS]);
}

function show_trace_view(ctx, model) {
	if (model == undefined) {
		model = Backtracer.ACCURATE;
	}

	// Model = Backtracer.FUZZY;
	send([Thread.backtrace(ctx, model).map(DebugSymbol.fromAddress).join('\n') + TRACE_TAG, VIEW_TRACE]);
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
//	libc_base_address = base;
//	globalLib = base;
//	globalBreakpoint = "0x" + offset.toString(16);
//	globalLibName = name;
//	globalContext = ctx;
	send([data, VIEW_CODE + arch]); // 标记为送往code段的数据
}

// 显示所有布局视图
function show_view(context) {
	init_segment_address(context);
	show_registers(context);
	show_telescope_view(context.sp, VIEW_STACK); // 栈空间视图
	show_code_view(context);
	// Show_trace_view(context,Backtracer.FUZZY)
}

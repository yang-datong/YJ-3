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
var isAutoShowView = true;

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
	isAutoShowView = mjson.isAutoShowView;
};

// --------------------- Initialized variables ----------------------
const message_tag = ' log ';
let step; let arch;
var globalContext, globalLibName, globalLibBase, globalBreakpoint, globalLibPath;
// Var globalContext, globalLibName, globalLibBase, globalBreakpoint, globalLibPath;

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
			// TODO 多级指针
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
// const maxSkipCount = 3;
// const skipCount = maxSkipCount;
// const skipCache = '';
// const REGISTER_FAZY_ZERO_VALUE_FILTERING_MODE = false;
// const REGISTER_CHECK_IS_LR_MODE = true;

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

function show_code_view() {
	const offset = Number.parseInt(globalBreakpoint);
	const path = globalLibPath;
	const name = globalLibName;
	const object = {name, offset, path};
	const data = JSON.stringify(object) + CODE_TAG;
	send([data, VIEW_CODE + arch]); // 标记为送往code段的数据
}

// 显示所有布局视图
function show_view(context) {
	init_segment_address(context);
	show_registers(context);
	show_telescope_view(context.sp, VIEW_STACK); // 栈空间视图
	show_code_view();
	// Show_trace_view(context,Backtracer.FUZZY)
}

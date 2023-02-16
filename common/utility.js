// ------------------------- Alias -------------------------------
const log = (...info) => {
	const befor = Array.from({length: _width - END_LINE_LEN - message_tag.length + 1}).join('=');
	const end = new Array(END_LINE_LEN).join('=');
	console.log(befor + message_tag + end + '\n');
	console.log(...info);
};

const dump = (...ptr) => {
	if (ptr[1] == undefined) {
		ptr[1] = 0x30;
	}

	return send(hexdump(ptr[0], {offset: 0, length: ptr[1], header: true, ansi: true}));
};

const tele = (...args) => {
	show_telescope_view(...args);
};

const ls = ctx => {
	show_view(ctx);
};

// 用于Interceptor.attach的封装
function b(...args) {
	const addr = args[0];
	const on_enter = args[1];
	const on_leave = args[2];
	const is_clear = args[3];

	// 初始化lib信息，存入全局变量中
	const lib = Process.getModuleByAddress(addr);
	globalLibBase = lib.base;
	globalBreakpoint = '0x' + (addr - Number.parseInt(lib.base)).toString(16);
	globalLibName = lib.name;
	globalLibPath = lib.path;

	Interceptor.attach(addr, {
		onEnter(_args) {
			if (is_clear != undefined) {
				send(CLEAR_TAG);
			}

			if (on_enter != undefined) {
				on_enter(this.context);
			}

			globalContext = this.context;
		}, onLeave(_returnValue) {
			if (on_leave != undefined) {
				on_leave(this.context);
			}
		},
	});
}

// ------------------- Used to provide python call ------------------
rpc.exports.libcBaseAddress = () => globalLibBase;

rpc.exports.getBreakpoints = () => globalBreakpoint + ' ' + globalLibName;

rpc.exports.readPointer = address => {
	try {
		return new NativePointer(address).readPointer();
	} catch (error) {
		console.log(error);
		return 0;
	}
};

rpc.exports.telescope = address => {
	try {
		show_telescope_view(new NativePointer(address), VIEW_TELESCOPE);
	} catch (error) {
		console.log(error);
	}
};

rpc.exports.hexdump = function (address, size) {
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

rpc.exports.showAllView = _address => {
	try {
		show_view(globalContext);
	} catch (error) {
		console.log(error);
	}
};

rpc.exports.setBreakpoint = (address, targetLibName) => {
	try {
		setBreakpoint(address, targetLibName);
	} catch (error) {
		console.log(error);
		deleteBreakpoint(address);
	}
};

function setBreakpoint(address, targetLibName) {
	let targetLibBase;
	// Console.log("address->"+address+",targetLibName->"+targetLibName);
	// console.log("globalBreakpoint->"+globalBreakpoint+",globalLibName->"+globalLibName);
	if (globalBreakpoint != undefined && address.toLowerCase() == globalBreakpoint.toLowerCase()) {
		console.log('Don\'t duplicate addtion -> ' + globalBreakpoint);
		return;
	}

	if (targetLibName == undefined || targetLibName === '') {
		targetLibName = globalLibName;
	}

	if (targetLibName == undefined) {
		console.log('Currentil not found available target dynamic lib. Exec -> b [address] [targetLibName]');
		return;
	}

	if (targetLibName != globalLibName) {
		targetLibBase = Module.findBaseAddress(targetLibName);
		if (targetLibBase == null) {
			console.log('Don\'t find ' + targetLibName);
			return;
		}

		globalLibBase = targetLibBase;
	}
	// Console.log("address->"+address+",targetLibName->"+targetLibName);
	// console.log("globalBreakpoint->"+globalBreakpoint+",globalLibName->"+globalLibName);

	Interceptor.detachAll(); // 现在支持单个断点 hook 以后会考虑 TODO
	b(globalLibBase.add(address), c => {
		ls(c);
	});

	console.log('SetBreakpoint -> {lib:' + globalLibName + ',address:' + address + '}');
}

rpc.exports.deleteBreakpoint = address => {
	try {
		deleteBreakpoint(address);
	} catch (error) {
		console.log(error);
	}
};

function deleteBreakpoint(_address) {
	Interceptor.detachAll();
	globalLibBase = undefined;
	globalContext = undefined;
	globalLibName = undefined;
	globalBreakpoint = undefined;
	globalLibPath = undefined;
//	Interceptor.revert(new NativePointer("0x" + (Number.parseInt(address) + Number.parseInt(globalLibBase.base)).toString(16)));
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

rpc.exports.showAllso = (user, output) => showAllso(user, output);
function showAllso(user, output) {
	let list_name = '';
	Process.enumerateModules({
		onMatch(so) {
			const path = so.path;
			if (user) {
				if (path.includes('/data/app/')) {
					list_name += output == undefined || output == true ? so.path + ',' : so.name + ' -> {size : 0x' + so.size.toString(16) + '. base : 0x' + so.base.toString(16) + '}' + ',';
				}
			} else if (output == undefined || output == true) {
				list_name += so.path + ',';
			} else {
				list_name += so.name + ' -> {size : 0x' + so.size.toString(16) + '. base : 0x' + so.base.toString(16) + '}' + ',';
			}
		}, onComplete() {},
	});
	return list_name;
}

let globalWatchLibName; let globalWatchLibRange;
rpc.exports.watchMemory = (watchLibName, length) => {
	try {
		watchMemory(watchLibName, length);
	} catch (error) {
		unWatchMemory();
		console.log(error + ' -> Try "info so"');
	}
};

function watchMemory(watchLibName, length) {
	const lib = Process.getModuleByName(watchLibName);
	if (length == null) {
		length = lib.size;
		// Watch .text memory ->
		// offset = objdump -h libxxx.so | grep .text | awk '{print $4}'
		// length = objdump -h libxxx.so | grep .text | awk '{print $3}'
	} else {
		length = Number.parseInt(length);
	}

	unWatchMemory(); // Detecation befor whether live watchMemory
	const baseAddressPointer = lib.base;
	_watchMemory(baseAddressPointer, length);
	globalWatchLibName = watchLibName;
	globalWatchLibRange = '[ ' + baseAddressPointer + ' - ' + baseAddressPointer.add(length) + ' ]';
	console.log('Watchmemory -> { name : ' + globalWatchLibName + ',range : ' + globalWatchLibRange + ',size : 0x' + length.toString(16));
}

// 监控内存数据
function _watchMemory(pointer, length) {
	MemoryAccessMonitor.enable({base: pointer, size: length}, {
		onAccess(details) {
			send('watchMemory change -> { '
				+ '\n\tname: ' + globalWatchLibName + globalWatchLibRange
				+ '\n\toperation : ' + details.operation
				+ '\n\tfrom : ' + details.from
				+ '\n\taddress : ' + details.address
				+ '\n\trangeIndex : ' + details.rangeIndex
				+ '\n\tpageIndex : ' + details.pageIndex
				+ '\n\tpagesCompleted : ' + details.pagesCompleted
				+ '\n\tpagesTotal : ' + details.pagesTotal
				+ '\n}',
			);
		}});
}

rpc.exports.unWatchMemory = () => {
	unWatchMemory();
};

function unWatchMemory() {
	if (globalWatchLibName != null && globalWatchLibRange != null) {
		MemoryAccessMonitor.disable();
		send('Detecationed ' + globalWatchLibName + globalWatchLibRange + ' -> disable');
		globalWatchLibName = null;
		globalWatchLibRange = null;
	}
}

// Java level to back tracer
function jbacktracer() {
	const back = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new());
	send('Java Stack -> :\n' + back);
}

rpc.exports.getExportFunc = libName => {
	try {
		getExportFunc(libName);
	} catch (error) {
		console.log(error);
	}
};

// Lib all exports function
function getExportFunc(libName) {
	const exports = Module.enumerateExports(libName);
	console.log('Export -> { ');
	for (const it of exports) {
		console.log('\tname : ' + it.name
					 			+ ', type: ' + it.type
								+ ', address: ' + it.address);
	}

	console.log('\n}');
}

rpc.exports.getImportFunc = libName => {
	try {
		getImportFunc(libName);
	} catch (error) {
		console.log(error);
	}
};

// Lib all imports function
function getImportFunc(libName) {
	const imports = Module.enumerateImports(libName);
	console.log('Import -> { ');
	for (const it of imports) {
		console.log('\tname : ' + it.name
					 			+ ', type: ' + it.type
								+ ', address: ' + it.address);
	}

	console.log('\n}');
}

rpc.exports.getJNIFunc = () => {
	try {
		getJNIFunc();
	} catch (error) {
		console.log(error);
	}
};

// JNI function
function getJNIFunc() {
	const symbols = Module.enumerateSymbols('libart.so');
	for (const it of symbols) {
		const name = it.name;
		if (name.includes('JNI')
				&& !name.includes('CheckJNI')
				&& name.includes('art')
				&& name.includes('GetStringUTFChars')) {
			console.log(name);
		}
	}
}

rpc.exports.writeFile = (content, fileName) => {
	try {
		writeFile(content, fileName);
	} catch (error) {
		console.log(error);
	}
};

// Save data to file
function writeFile(content, fileName) {
	fileName = '/sdcard/' + fileName;
	const file = new File(fileName, 'w+');
	file.write(content);
	file.flush();
	file.close();
	send('-----> save: ' + fileName + ' is done!! <------');
}

rpc.exports.javaHookClassAllFunctions = pack => {
	try {
		javaHookClassAllFunctions(pack);
	} catch (error) {
		console.log(error);
	}
};

// Hook all functions of a single class in the java level
// @parameter pack : "com.xx.xx.class"
function javaHookClassAllFunctions(pack) {
	const cls = Java.use(pack);
	const methods = cls.class.getDeclaredMethods();
	for (const it of methods) {
		var methodName = it.getName();
		console.log(methodName);
		for (let i = 0; i < cls[methodName].overloads.length; i++) {
			cls[methodName].overloads[i].implementation = () => {
				console.log(cls[methodName]);
				for (const argument of arguments) {
					console.log(argument);
				}

				return Reflect.apply(this[methodName], this, arguments);
			};
		}
	}
}

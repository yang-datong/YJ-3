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
}

const ls = (ctx) => {
	show_view(ctx);
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

			if (on_enter != undefined) {
				on_enter(this.context);
			}
			globalContext = this.context;
		}, onLeave(returnValue) {
			if (on_leave != undefined) {
				on_leave(this.context);
			}
		},
	});
}

// ------------------------- Function -------------------------------
rpc.exports.showAllso = (user, output) => showAllso(user, output);

function showAllso(user, output) {
	let list_name = '';
	Process.enumerateModules({
		onMatch(so) {
			const path = so.path;
			if (user) {
				if (path.includes('/data/app/')) {
					list_name += so.name + ' ';
				}
			} else {
				list_name += so.name + ' ';
			}
		}, onComplete() {
			if (output == undefined || output == true) {
			  console.log('{' + list_name + '}');
			}
		},
	});
	return list_name;
}

//TODO 添加watch命令 配合 info so 来试探内存

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

// Android层栈回溯
function jbacktracer() {
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

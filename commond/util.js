//-------------------------define-------------------------------
//配置信息区
var END_LINE_LEN
var VIEW_MESSAGE 
var VIEW_STACK 
var VIEW_CODE 
var VIEW_TRACE
var VIEW_REGISTERS 
var CLEAR_TAG 
var TELE_TAG 
var CODE_TAG 
var TRACE_TAG 
var REGISTER_TAG
var INIT_SEGMENT_ADDRESS_TAG
var TELE_SHOW_ROW_NUMBER
rpc.exports.init = mjson => {
	END_LINE_LEN = mjson['end_line_len']
	VIEW_MESSAGE = mjson['view_message']
	VIEW_STACK = mjson['view_stack']
	VIEW_CODE = mjson['view_code']
	VIEW_TRACE = mjson['view_trace']
	VIEW_REGISTERS = mjson['view_registers']
	CLEAR_TAG = mjson['clear_tag']
	CODE_TAG = mjson['code_tag']
	TRACE_TAG = mjson['trace_tag']
	TELE_TAG = mjson['tele_tag']
	REGISTER_TAG = mjson['register_tag']
	INIT_SEGMENT_ADDRESS_TAG  = mjson['init_segment_address_tag']
	TELE_SHOW_ROW_NUMBER = mjson['tele_show_row_number']
}
//变量区
var message_tag = " log "
var _width = 70
var step = 4  //默认32bit
var arch 

const log = (...info) => {
    var befor = new Array(_width - END_LINE_LEN - message_tag.length + 1).join("=")
    var end = new Array(END_LINE_LEN).join("=")
    console.log(befor + message_tag + end + "\n")
	console.log(...info);
}

const dump = (...ptr) => { 
	if(ptr[1] == undefined)
		return send(hexdump(ptr[0],{offset:0,length:0x30,header:true,ansi:true}))
	else
		return send(hexdump(ptr[0],{offset:0,length:ptr[1],header:true,ansi:true}))
}
//-------------------------init-------------------------------
//这里是配置信息 需要进行配置上下文对象 往后会对64位so进行支持!!!
/**
		send("id->"+Process.id +
			"\narch->"+Process.arch + 
			"\nplatform->"+Process.platform +
			"\npageSize->"+Process.pageSize +
			"\nisDebuggerAttached->"+Process.isDebuggerAttached()+
			"\ngetCurrentThreadId->"+Process.getCurrentThreadId()+
			"\npointerSize->"+Process.pointerSize )
			*/
//findAll("初始化之前",lib)
//setTimeout((v0,v1) => {findAll(v0,v1)},1700,"初始化之后",lib)

//-------------------------alias-------------------------------
//以更简洁的方式调用（设置别名)
function tele(...args){ show_telescope_view(...args)}
function ls(ctx,lib_base){ show_view(ctx,lib_base)}

//-------------------------func-------------------------------
//监控内存数据
function watch(addr,len,lib){
	MemoryAccessMonitor.enable({base:addr,size:len},{
		onAccess(details){
			send("operation->"+details.operation+
				"\nfrom->"+details.from+
				"\naddress->"+(details.address)+
				"\nrangeIndex->"+details.rangeIndex+
				"\npageIndex->"+details.pageIndex+
				"\npagesCompleted->"+details.pagesCompleted+
				"\npagesTotal->"+details.pagesTotal
				)
		}})
}
//用于Interceptor.attach的封装
function b(...args){
	var addr = args[0]
	var on_enter = args[1]
	var on_leave = args[2]
	var is_clear = args[3]

	Interceptor.attach(addr,{
            onEnter(args){
				if(is_clear != undefined)
				send(CLEAR_TAG)
				//show_view(this.context)
				if(on_enter != undefined)
					on_enter(this.context)
            },onLeave(ret){
				if(on_leave != undefined)
					on_leave(this.context)
			}
        })
}


//显示一个指针块视图 
function show_telescope_view(...args){
	var data = ""
	var addr = args[0]
	var _addr , ptr
	for(var i = 0 ; i < TELE_SHOW_ROW_NUMBER; i++){  
		_addr = addr.readPointer()
		try{
			ptr = _addr.readPointer()
		}catch(error){
			ptr = 0
		}
		data += (addr + "│" + (i*step) + "│" + _addr + "│" + ptr + TELE_TAG)
		addr = addr.add(step)
	}
	if(args[1] != null)
		send([data,args[1]])
	else
		send(data)
}
//寄存器视图
function show_registers(...args){
	var context = args[0]
	var data = ""
	var addr,ptr
	for(var key in context){
		addr = context[key]
		try{
			ptr = addr.readPointer()
		}catch(error){
			ptr = 0
		}
		data += (key + "│" + addr + "│"  + ptr + REGISTER_TAG)
	}
	send([data,VIEW_REGISTERS])
}
//向python块发送所需块数据
function init_segment_address(context){
	arch = " code:"+Process.arch+" "
	step = Process.pointerSize 
	var stack = context.sp
	var code = context.pc
	var data = stack + INIT_SEGMENT_ADDRESS_TAG + code + INIT_SEGMENT_ADDRESS_TAG + arch + INIT_SEGMENT_ADDRESS_TAG + step
	send(data)
}
//显示所有布局视图 
function show_view(context,lib_base){
	init_segment_address(context)  
	show_registers(context) 
	show_telescope_view(context.sp,VIEW_STACK) //栈空间视图
	show_code_view(context)
	//show_trace_view(context) //卡顿严重 暂时不开放!!!!
}
function show_trace_view(ctx){
	var data = Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + TRACE_TAG
	send([data,VIEW_TRACE])
}

function show_code_view(ctx){
//	send("id->"+Process.id +
//			"\narch->"+Process.arch + 
//			"\nplatform->"+Process.platform +
//			"\npageSize->"+Process.pageSize +
//			"\nisDebuggerAttached->"+Process.isDebuggerAttached()+
//			"\ngetCurrentThreadId->"+Process.getCurrentThreadId()+
//			"\npointerSize->"+Process.pointerSize )
	var lib = Process.getModuleByAddress(ctx.pc)
	var name = lib.name
	var base= lib.base
	var path = lib.path
	var offset = ctx.pc - parseInt(base)
	var obj = {"name":name,
				"base":base,
				"path":path,
				"offset":offset}

	var data = JSON.stringify(obj) + CODE_TAG 
	send([data,VIEW_CODE + arch]) //标记为送往code段的数据
}

//所有加载的so 
function findAll(str,lib){
	for(var i in lib){
		send(str + lib[i] + "-> "+Module.findBaseAddress(lib[i]))
	}
}

//so层栈回溯 
function printStack_so(ctx){
	send('So Stack -> :\n' +Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
	//log('So Stack -> :\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');

}
//Android层栈回溯 
function printStack(){
	send('Java Stack -> :\n' +Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
}
//so的所有导出函数 
function export_func(so){
    var exports = Module.enumerateExportsSync(so);
     for(var i = 0; i < exports.length; i++) {
       send(exports[i].name + ": " + exports[i].address+",so->"+so);
			 b(exports[i].address.add(1),c=>{
			 	send(exports[i].name)
			 })

         if(exports[i].name == "ByteVC1_dec_create")
       send(exports[i].name + ": " + exports[i].address+",so->"+so);
    }
}

function import_func(so,target){
		//so的所有导入函数 
    var exports = Module.enumerateImportsSync(so);
     for(var i = 0; i < exports.length; i++) {
       //send(exports[i].name + ": " + exports[i].address+",so->"+so);
         if(exports[i].name == target)
				 send("Find!!!"+so+"->"+exports[i].name)
	}
}
//so的所有导入函数 
function hook_libart() {
    var GetStringUTFChars_addr = null;
    var module_libart = Process.findModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var name = symbols[i].name;
        if ((name.indexOf("JNI") >= 0)
						&& (name.indexOf("CheckJNI") == -1)
						&& (name.indexOf("art") >= 0)) {
            if (name.indexOf("GetStringUTFChars") >= 0) {
                log(name);
                // 获取到指定 jni 方法地址
                GetStringUTFChars_addr = symbols[i].address;
            }}}
}
//保存数据到文件
function writeFile(content,file_name) {
	var file = new File("/sdcard/"+file_name,"w+");//a+表示追加内容，此处的模式和c语言的fopen函数模式相同
	file.write(content);
	file.flush()
	file.close();
	send("-----> save: "+file_name+" is done!! <------")
}

function calss_methods(){
//hook类的所有方法
        var md5Util=Java.use("com.ss.texturerender.VideoSurfaceTexture");
        var methods=md5Util.class.getDeclaredMethods();
        for(var j=0;j<methods.length;j++){
            var methodName=methods[j].getName();
            console.log(methodName);

            //这里遍历方法的所有重载
            for(var i=0;i<md5Util[methodName].overloads.length;i++){
                md5Util[methodName].overloads[i].implementation=function(){
                    for(var k=0;k<arguments.length;k++){
                        console.log(arguments[k]);
                    }
                    //这里需要调用原来的方法，但是原来的方法的参数个数不确定，所以需要使用到arguments
                    return this[methodName].apply(this,arguments);
                }
            }
        }
}

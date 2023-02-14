// ------------------------- Main -------------------------------
//java()
//hook('libc.so','fread')
//hook('libc.so','fwrite')
//32bit app -> address + 1
// ----------------------- Function -------------------------------
function main(){
    Process.enumerateModules({
            onMatch: function(exp){
                console.log(exp.path);
                //console.log(exp.name + "|" + exp.base + "|" + exp.size + "|" + exp.path);
                //if(exp.name == 'libart.so'){
                    // console.log(exp.name + "|" + exp.base + "|" + exp.size + "|" + exp.path);
                    // console.log(JSON.stringify(exp));
                    //return 'stop';
                //}
            },
            onComplete: function(){
                send('stop');
            }
        });
}

function java() {
	Java.perform(() => {
		Java.use('java.lang.System').exit.implementation = function () {
			console.log('[*] System.exit called');
		};
	});
}

function hook(so,func) {
	var addr = Module.getExportByName(so,func);
	b(addr, c => {
		ls(c);
	});
}

//-------------------------mian-------------------------------
//java()
hook("libttmplayer.so",0x103418)
//hook("libjato.so",0x12B05)
//hooks("libttmplayer.so",0x145384)
//-------------------------func-------------------------------
function java(){
	send("1")
	Java.perform(()=>{
		Java.use("com.ss.ttm.player.TTPlayer").setVideoSurface.overload('android.view.Surface').implementation = function(v1){
			send(""+this.mHandle.value)
        return this.setVideoSurface(v1)
		}
})
}


function hook(so,addr){
	   var lib = Module.findBaseAddress(so)
    while(lib == null){
        lib = Module.findBaseAddress(so)
    }
    b(lib.add(addr),c=>{
        ls(c)
        tele(c.x8)
    })

}

function hooks(so,addr){
	   var lib = Module.findBaseAddress(so)
    while(lib == null){
        lib = Module.findBaseAddress(so)
    }
	send("find!"+so)
Interceptor.attach(lib.add(addr),{
	onEnter(args){
		send("1111")
	},onLeave(ret){
}})
}


var exitClass = ""
setImmediate(function() {
    Java.perform(function() {
        console.log("[*] Hooking calls to System.exit");
        exitClass = Java.use("java.lang.System");
        exitClass.exit.implementation = function() {
            console.log("[*] System.exit called");
        }
 
        var strncmp = undefined;
        var imports = Module.enumerateImportsSync("libfoo.so");
 
        for(var i = 0; i < imports.length; i++) {
            if(imports[i].name == "strncmp") {
                strncmp = imports[i].address;
                break;
            }
 
        }
 
});})


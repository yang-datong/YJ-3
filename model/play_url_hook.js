// -------------------------define-------------------------------
// -------------------------mian-------------------------------
var fileHead;
var index = 0;
Java.perform(() => {
	const cls  = Java.use("com.ss.ttvideoengine.TTVideoEngineLegacy")
	cls._logFirstFrame.overload().implementation = function(){
		//send("_logFirstFrame")
		const media_cls = Java.use("com.ss.ttvideoengine.MediaPlayerWrapper")
		//const ret = media_cls.getDataSource()
		//console.log(ret);
		media_cls.getIntOption.overload('int','int').implementation = function(v0,v1){
			//send("getIntOption")
			//send(this)
			const ret = this.getDataSource()
			if (ret.startsWith('mem:')) {
				fileHead = "mem_"
				console.log("mem");
			}
			else if (ret.startsWith('mdl:')) {
				fileHead = "mdl_"
				console.log("mdl:");
			}
			else if (ret.startsWith('http:')) {
				fileHead = "http_"
				console.log("http:");
			}else{
				fileHead = "none_"
				console.log(ret);
			}
			writeFile(ret,"url/"+  fileHead + "url" +index++  +  ".txt")
			return this.getIntOption(v0,v1)
		}
	}
})

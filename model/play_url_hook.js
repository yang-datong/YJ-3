// -------------------------define-------------------------------
// -------------------------mian-------------------------------
let fileHead;
let index = 0;
Java.perform(() => {
	const cls = Java.use('com.ss.ttvideoengine.TTVideoEngineLegacy');
	cls._logFirstFrame.overload().implementation = function () {
		// Send("_logFirstFrame")
		const media_cls = Java.use('com.ss.ttvideoengine.MediaPlayerWrapper');
		// Const ret = media_cls.getDataSource()
		// console.log(ret);
		media_cls.getIntOption.overload('int', 'int').implementation = function (v0, v1) {
			// Send("getIntOption")
			// send(this)
			const returnValue = this.getDataSource();
			if (returnValue.startsWith('mem:')) {
				fileHead = 'mem_';
				console.log('mem');
			} else if (returnValue.startsWith('mdl:')) {
				fileHead = 'mdl_';
				console.log('mdl:');
			} else if (returnValue.startsWith('http:')) {
				fileHead = 'http_';
				console.log('http:');
			} else {
				fileHead = 'none_';
				console.log(returnValue);
			}

			writeFile(returnValue, '/sdcard/url/' + fileHead + 'url' + index++ + '.txt');
			return this.getIntOption(v0, v1);
		};
	};
});

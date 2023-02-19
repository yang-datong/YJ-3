// ------------------------- Define -------------------------------
rpc.exports = {
	init(stage, parameters) {
	// Enter function
		log('Start exec explore.js .current argrment->{stage:' + stage + ',parameters:' + JSON.stringify(parameters) + '}');
		main();
		log('Exec done~');
	},
};
// ------------------------- Main -------------------------------
function main() {
	// Enter




}


// ------------------------- Utility  -------------------------------
function log(string_) {
	string_ = JSON.stringify(string_);
	writeFile(string_ + '\n', '/sdcard/yj.log', 'ab');
}

// Save data to file
function writeFile(content, fileName,opt) {
	if(fileName == undefined || fileName == null){
		var currentdate = new Date();
		fileName = '/sdcard/YJ-'+ currentdate.getDate() + "-"
                 + (currentdate.getMonth()+1)  + "-"
                 + currentdate.getFullYear() + "-"
                 + currentdate.getHours() + "-"
                 + currentdate.getMinutes() + "-"
                 + currentdate.getSeconds() + ".dat";
	}
	let file = null;
	let _opt = "wb"
	try{
		if (opt != undefined || opt != null) {
			_opt = opt;
		}
		console.log(_opt);
		file = new File(fileName, _opt);
		file.write(content);
		file.flush();
		file.close();
		send('-----> save: ' + fileName + ' is done!! <------');
	}catch(e){
		console.log(e + " -> " + fileName);
		if (file) {
			file.flush();
			file.close();
		}
	}
}

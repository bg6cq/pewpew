var PORT = 4000;
var HOST = '0.0.0.0';

var dgram = require('dgram');
var udpserver = dgram.createSocket('udp4');

udpserver.on('listening', function () {
    	var address = udpserver.address();
    	console.log('UDP Server listening on ' + address.address + ":" + address.port);
});

udpserver.bind(PORT, HOST);

function ab2str(buf) {
	return String.fromCharCode.apply(null, new Uint8Array(buf));
}

udpserver.on('message', function (msg, remote) {
	console.log(remote.address + ':' + remote.port +' - ' + msg);
	var txt = ab2str(msg);
       console.log(txt);
	var obj = JSON.parse(txt);
	io.emit('attack', obj);
});

var express = require('express'); // Get the module
var app = express(); // Create express by calling the prototype in var express
var http = require('http').Server(app);
var io = require('socket.io')(http);

app.use(express.static('html'));

app.get('/', function(req, res){
	res.sendFile(__dirname + 'html' + '/index.html');
});

io.on('connection', function(socket){
	console.log('websocket user '+socket.id+' connected');
	socket.on('disconnect', function(){
		console.log('websocket user '+socket.id+' disconnected');
	});
});

http.listen(4000, function(){
	console.log('listening on *:4000');
});


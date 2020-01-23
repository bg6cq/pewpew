var PORT = 4000;
var HOST = '127.0.0.1';

var dgram = require('dgram');
var udpserver = dgram.createSocket('udp4');

udpserver.on('listening', function () {
    	var address = udpserver.address();
    	console.log('UDP Server listening on ' + address.address + ":" + address.port);
});

udpserver.bind(PORT, HOST);

udpserver.on('message', function (msg, remote) {
//	console.log(remote.address + ':' + remote.port +' - ' + msg);
	txt = msg.toString();
//       console.log(txt);
	var obj = JSON.parse(txt);
	io.emit('attack', obj);
});

var express = require('express'); // Get the module
var app = express(); // Create express by calling the prototype in var express
var http = require('http').Server(app);
var io = require('socket.io')(http);

app.use(function(req, res, next) {
	if(req.headers.host!="whoisscanme.ustc.edu.cn:4000") {
                res.statusCode = 404;
                res.write('<p> Unknow host ' + req.headers.host);
                console.log('unknow host: '+req.headers.host);
        }
	next();
}, express.static('html'));

io.on('connection', function(socket){
	console.log('websocket user '+socket.id+' connected');
	socket.on('disconnect', function(){
		console.log('websocket user '+socket.id+' disconnected');
	});
});

http.listen(4000, function(){
	console.log('listening on *:4000');
});

<?php

// 获得PORTSCAN fromip fromport toip toport 输入
// 输出 { "fromip": fromip, "toip": toip, "fromport": fromport, "toport": toport, "srclat": srclat, "srclong": srclong, "tolat": tolat, "tolong": tolong, 
//        "fromcountry": fromcountry, "tocountry": tocountry, "color": color, "msg": msg }
//

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

if($socket == FALSE) {
	echo "socket_create error!\n";
	exit(0);
}

if (!socket_bind($socket, "127.0.0.1", 4001)) {
	$errorcode = socket_last_error();
	$errormsg = socket_strerror($errorcode);
        echo "bind socket失败: [$errorcode] $errormsg\n";
	exit(0);
}
echo 'socket bind成功...\n';

$redports = array (22, 1433, 1521, 3306, 3389);
$greenports = array (23, 25, 80, 123, 443, 8080, 8443);

$lasttime = time();
while (true) {
	$r = socket_recvfrom($socket, $buf, 512, 0, $remote_ip, $remote_port);
	
	list($event, $fromip, $fromport, $toip, $toport)  = explode(" ", $buf);

	if($event!="PORTSCAN") {
		echo "unknow message ".$event."\n";
		continue;
	}
	
	$fromip = inet_ntop(inet_pton($fromip));
	$toip = inet_ntop(inet_pton($toip));
	$fromport = intval($fromport);
	$toport = intval($toport);

	echo "$fromip $fromport $toip $toport\n";

	$fromcountry = geoip_country_code_by_name($fromip);
	if($fromcountry == "") 
		$fromcountry = "US";
	$tocountry = geoip_country_code_by_name($toip);
	if($tocountry == "") 
		$tocountry = "US";
	$msg = "port scan from $fromport to $toport";

	if(in_array($toport, $redports)) 
		$color = "red";
	else if(in_array($toport, $greenports)) 
		$color = "green";
	else {
		if($lasttime == time())  // 这一秒有事件，碰到不重要的跳过去不显示
			continue;
		$color = "green";
	}

	$lasttime = time();
	
	$buf = '{"fromip": "'.$fromip.'", "fromport": "'.$fromport.'", "toip": "'.$toip.'", "toport": "'.$toport.'", "fromcountry": "'.$fromcountry.'", "tocountry": "'.$tocountry.'", "msg": "'.$msg.'", "color": "'.$color.'"}';
	echo $buf."\n";
	
	socket_sendto($socket, $buf, strlen($buf), 0, "127.0.0.1", 4000);
}

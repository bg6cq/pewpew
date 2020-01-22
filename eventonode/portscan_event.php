<?php

// 获得PORTSCAN fromip fromport toip toport 输入
// 输出 { "fromip": fromip, "toip": toip, "fromport": fromport, "toport": toport, "srclat": srclat, "srclong": srclong, "tolat": tolat, "tolong": tolong, 
//        "fromcountry": fromcountry, "tocountry": tocountry, "color": color, "msg": msg }
//

$db_host = "localhost";
$db_user = "root";
$db_passwd = "";
$db_dbname = "scanlog";

$mysqli = new mysqli($db_host, $db_user, $db_passwd, $db_dbname);
if(mysqli_connect_error()){
	echo mysqli_connect_error();
}

function getipdesc($ip) {
	if(strchr($ip,":")) // ipv6
		$u = "ipv6";
	else {
        	$url = "http://210.45.224.10:90/".$ip;
		$u = file_get_contents($url);
	}
	return $u;
}


function get_lat_long($ip, &$country, &$lat, &$long) {
	global $mysqli;
	$u = getipdesc($ip);
	list ($a, $b, $c) = explode("	", $u);
	//echo "c:".$a." ".$b.$c."\n";
	if($b == $c)
		$name = $b;
	else
		$name = $b.$c;
	$q = "select `lat`, `long` from namelatlong where name = ?";
	$stmt=$mysqli->prepare($q);
	$stmt->bind_param("s",$name);
	$stmt->execute();
	$stmt->bind_result($tlat, $tlong);
	if($stmt->fetch()){
		$lat = $tlat;
		$long = $tlong;
		$country=$name;
//		echo "lat/long:".$lat."/".$long."\n";
		$stmt->close();
	} else {
		$stmt->close();
		$q = "replace into unknowname values(?)";
		$stmt=$mysqli->prepare($q);
        	$stmt->bind_param("s",$name);
        	$stmt->execute();
		$stmt->close();
	}
}

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
echo "socket bind成功...\n";

$redports = array (22, 110, 1433, 1521, 3306, 3389);
$greenports = array (21, 23, 25, 53, 80, 123, 443, 1080, 8080, 8443);

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
	$fromlat = "";
	$fromlong = "";
	$tolat = "";
	$tolong = "";

	echo "$fromip $fromport $toip $toport\n";

	$fromcountry = @geoip_country_code_by_name($fromip);
	if($fromcountry == "") 
		$fromcountry = "US";
	$tocountry = @geoip_country_code_by_name($toip);
	if($tocountry == "") 
		$tocountry = "US";

	get_lat_long($fromip, $fromcountry, $fromlat, $fromlong);
	get_lat_long($toip, $tocountry, $tolat, $tolong);

	$msg = "port scan from $fromport to $toport";

	if(in_array($toport, $redports)) 
		$color = "red";
	else if(in_array($toport, $greenports)) 
		$color = "green";
	else {
		if($lasttime == time())  // 这一秒有事件，碰到不重要的跳过去不显示
			continue;
		$color = "gray";
	}

	$lasttime = time();
	
	$buf = '{"fromip": "'.$fromip.'", "fromport": "'.$fromport.'", "toip": "'.$toip.'", "toport": "'.$toport.'", "fromcountry": "'.$fromcountry.'", "tocountry": "'.$tocountry.'",';
	if($fromlat != "") 
		$buf = $buf .  '"fromlat": '.$fromlat.',';
	if($fromlong != "") 
		$buf = $buf .  '"fromlong": '.$fromlong.',';
	if($tolat != "") 
		$buf = $buf .  '"tolat": '.$tolat.',';
	if($tolong != "") 
		$buf = $buf . '"tolong": '.$tolong.',';
	$buf = $buf .  '"msg": "'.$msg.'", "color": "'.$color.'"}';
	echo $buf."\n\n";
	
	socket_sendto($socket, $buf, strlen($buf), 0, "127.0.0.1", 4000);
}

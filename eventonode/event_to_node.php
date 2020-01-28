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
		$lat = 0;
		$long = 0;
		$country = "未知";
	}
}

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

if($socket == FALSE) {
	echo "socket_create error!\n";
	exit(0);
}

if (!socket_bind($socket, "0.0.0.0", 4001)) {
	$errorcode = socket_last_error();
	$errormsg = socket_strerror($errorcode);
        echo "bind socket失败: [$errorcode] $errormsg\n";
	exit(0);
}
echo "socket bind成功...\n";

$redports = array (22, 110, 1433, 1521, 3306, 3389);
$greenports = array (21, 23, 25, 53, 80, 123, 443, 1080, 8080, 8443);

$colors = array("red", "green", "gray", "blue", "pink");
$color_index = 0;

$lasttime = time();
while (true) {
        $fromlat = "";
        $fromlong = "";
        $tolat = "";
        $tolong = "";
	$r = socket_recvfrom($socket, $buf, 512, 0, $remote_ip, $remote_port);
	@list($event, $fromip, $fromport, $toip, $toport, $msg)  = @explode(" ", $buf);

        $fromip = inet_ntop(inet_pton($fromip));
        $toip = inet_ntop(inet_pton($toip));
	$fromport = intval($fromport);
	$toport = intval($toport);
	
	echo "event: $event $fromip $fromport $toip $toport\n";

        if($event=="MAILSCAN")
                 $msg = "mail scan";
        else if($event=="WAF")
                 $msg = "web attack";
        else if($event=="PORTSCAN")
		$msg = "port scan from $fromport to $toport";
        else if($event=="BLOCKIP") {
		if($toip == "0.0.0.0")
			$toip = "202.38.64.1";
	} else {
                echo "unknow message ".$event."\n";
                continue;
        }

        get_lat_long($fromip, $fromcountry, $fromlat, $fromlong);
        get_lat_long($toip, $tocountry, $tolat, $tolong);

	if($event != "PORTSCAN")
        	$color = "yellow";
	else {
		if(in_array($toport, $redports)) 
			$color = "red";
		else if(in_array($toport, $greenports)) 
			$color = "green";
		else {
			if($lasttime == time())  // 这一秒有事件，碰到不重要的跳过去不显示
				continue;
			$color = "gray";
		}

		$color_index = ($color_index + 1) % count($colors);

		$color = $colors[$color_index];

		$lasttime = time();
	}

	$buf = '{"event": "'.$event.'", "fromip": "'.$fromip.'", "fromport": "'.$fromport.'", "toip": "'.$toip.'", "toport": "'.$toport.'", "fromcountry": "'.$fromcountry.'", "tocountry": "'.$tocountry.'",';
	$buf = $buf .  '"fromlat": '.$fromlat.',';
	$buf = $buf .  '"fromlong": '.$fromlong.',';
	$buf = $buf .  '"tolat": '.$tolat.',';
	$buf = $buf . '"tolong": '.$tolong.',';
	$buf = $buf .  '"msg": "'.$msg.'", "color": "'.$color.'"}';
	echo $buf."\n\n";
	
	socket_sendto($socket, $buf, strlen($buf), 0, "127.0.0.1", 4000);
}

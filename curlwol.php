<?php
// should install this: php5-curl
function https_get($url){
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, 1);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, 2);
        $output = curl_exec($curl);
        list($header, $body) = explode("\r\n\r\n", $output, 2);
        curl_close($curl);
        return $body;
}

function goWakeonlan($macs=array(), $ips=array(), $masks=array())
{
    // get the gohosts in default.ini
    $ini_array = parse_ini_file(__DIR__."/default.ini",true);
    $wol_server = $ini_array['wol_server'];
    $hosts = $wol_server['gohosts'];
    $succed_no = 0;
    foreach ($hosts as $host) {
        for ($i = 0; $i < count($macs); $i++) {
            // get rid of out of index in array
            array_push($ips, "255.255.255");
            array_push($masks, "22");
            $url = "http://". $host .":8181/wake?mac=". $macs[$i] ."&ip=". $ips[$i] ."&mask=". $masks[$i];
            $get_result = https_get($url);
            $get_result ? : ($succed_no += 1);
        }
    }
    return $succed_no;
}

echo goWakeonlan(array("98:90:96:d0:5f:11","aa:aa:aa:aa:aa:aa"), array("10.32.99.199","1.2.3.4"), array(20));
echo goWakeonlan(array("98:90:96:d0:5f:11","aa:aa:aa:aa:aa:aa"), array("1.2.99.199"));
//echo goWakeonlan("98:90:96:d0:5f:11",array("10.32.99.199","1.2.3.4"), array(20));
//echo goWakeonlan(array("98:90:96:d0:5f:11"), array());
//echo goWakeonlan(array("98:90:96:d0:5f:11"));
//echo goWakeonlan(array("98:90:96:d0:5f:11"), , array());

?>

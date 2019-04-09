<?php
require_once 'radius_functions.php';
date_default_timezone_set('Europe/Vienna');
error_reporting(E_ALL & ~E_NOTICE);

define('IMPORT_OLD',false);
define('USERADIUSTIME',true);
define('PATH',"C:\\Windows\\System32\\LogFiles\\IN");
define('DBNAME','radius');
define('DBIP','192.168.1.117');
define('DBPORT',8090);
define('ONLYNEWDATA',true);
define('DAILYLOGS',false);

if(!IMPORT_OLD)
    /* Prduction: */
    follow(false);
else
{
	/* IMPORT_OLD data from 2010 to 2015 */
	for($year=10;$year<16;$year++)
	{
		for($i=1;$i<13;$i++)
		{
			$month = ($i<10)?'0'.$i:$i;
			follow($year.$month);
		}
	}
}


function saveLastTime($time)
{
    $fp = fopen('lasttime.txt','w');
    fwrite($fp,$time);
    fclose($fp);
}

function follow($forcedate=false)
{
    if(!$forcedate)
    {
        $datestring = DAILYLOGS?date("y").date("m").date("d"):date("y").date("m");
        $file = PATH.$datestring.'.log';
    }
    else 
    {
        $datestring = $forcedate;
        $file = PATH.$datestring.'.log';
    }
    
        
    if(ONLYNEWDATA)
    {
        $lasttime = implode(NULL,@file('lasttime.txt'));
    }

    $size = 0;
    while (true) {
        clearstatcache();
        $currentSize = filesize($file);
        if ($size == $currentSize){
			if(IMPORT_OLD){echo "[done]\n"; return;}
            usleep(100);
            continue;
        }
        
        // renew datestring and file name so it will automatically
        // choose the right file when the date changes
        if(!$forcedate)
        {
            $datestring = DAILYLOGS?date("y").date("m").date("d"):date("y").date("m");
            $file = PATH.$datestring.'.log';
        }

        $fh = fopen($file, "r");
        fseek($fh, $size);

        while ($d = fgets($fh))
        {
            $d = trim($d);
            $a = explode(',', $d);
            $server =   str_replace('"','',$a[0]);
            $date =     str_replace('"','',$a[2]);
            $time =     str_replace('"','',$a[3]);
            $timestamp = strtotime($date.' '.$time);
            
            if(ONLYNEWDATA && $timestamp<$lasttime) continue;
                
            saveLastTime($timestamp);

            $type =     str_replace('"','',$a[4]);
            $client =   str_replace('"','',$a[5]);
            $origin =   str_replace('"','',$a[6]);
            $client_mac =   trim(str_replace('"','',str_replace('-',':',$a[8])));
            if($client_mac && !strpos($client_mac,':'))
                $client_mac = chunk_split($client_mac, 2, ':');
            $ap_host =  str_replace('"','',$a[11]);
            $ap_ip =    str_replace('"','',$a[15]);
            $ap_radname=strtolower(str_replace('"','',substr($a[16], 0,5)));
            $ap_radname_full= strtolower(str_replace('"','',sanatizeStringForInflux($a[16])));
            $speed =    str_replace('"','',$a[20]);
            $policy =   str_replace('"','',$a[60]);
            $auth =   translateAuth(str_replace('"','',$a[23]));
            $policy2 =   str_replace('"','',$a[24]);
            $reason =   str_replace('"','',$a[25]);
            $rs = translateReason($reason);

            $tt = translatePackageType($type);
            $tq = round($timestamp/900)*900;

            //$origin_client = substr($origin, strpos($origin, '\\')+1);
            //if(!$origin_client) continue;
			
			if(strpos($origin,'\\'))
				$ab = explode('\\',$origin);
			else if(strpos($origin,'/'))
				$ab = explode('/',$origin);
				
			if(is_array($ab){
				
				if(count($ab)==4)
				{
					$origin_client = $ab[3];
					$OU = $ab[2];
				}
				else if(count($ab)==3)
				{
					$origin_client = $ab[2];
					$OU = $ab[1];
				}
				else if(count($ab)==2)
				{
					$origin_client = $ab[1];
					$OU = $ab[0];
				}
				else {
					$origin_client = $origin;
				}
				
			} 
			else
			{
				$origin_client = $origin;
			}

			$influxtime = $timestamp.'000000000';
            
            $OU = sanatizeStringForInflux($OU);
            $origin_client = sanatizeStringForInflux($origin_client);


            switch($type)
            {
                case 1: //Requesting access
                    if($requests[$origin_client.$ap_radname_full]==$timestamp) continue 2;
					
					$s = explode(' ',$speed);
					$speed = $s[1];
                    
                    $requests[$origin_client.$ap_radname_full]=$timestamp;
                    //echo date("d.m H:I:s",$timestamp).": $origin_client trying to connect via $ap_radname_full\n";

                    //making sure all tag values are set and if not, set them to "0"
					$client_mac = ($client_mac?$client_mac:'0');
                    $ap_radname_full = ($ap_radname_full?$ap_radname_full:'0');
                    $origin_client = ($origin_client?$origin_client:'0');

					sendToDB(DBNAME.",type=request,ap=$ap_radname_full,special=$client_mac,special_type=mac value=\"$origin_client\",special=\"$client_mac\"",$influxtime);
                break;

                case 2: //Accepted
                    //echo "$origin_client is accepted on $ap_radname_full\n\n";

                    //making sure all tag values are set and if not, set them to "0"
                    $OU = ($OU?$OU:'0');
                    $ap_radname_full = ($ap_radname_full?$ap_radname_full:'0');
                    $origin_client = ($origin_client?$origin_client:'0');

                    sendToDB(DBNAME.",type=accept,ap=$ap_radname_full,special=$OU,special_type=OU value=\"$origin_client\"",$influxtime);
                break;

                case 3: //Rejected
                    //echo "$origin_client is rejected because: $rs\n\n";
                    
                    //making sure all tag values are set and if not, set them to "0"
                    $ap_radname_full = ($ap_radname_full?$ap_radname_full:'0');
                    $reason = ($reason?$reason:'0');
                    $origin_client = ($origin_client?$origin_client:'0');
                    $rs = ($rs?$rs:'0');
                    sendToDB(DBNAME.",type=rejected,ap=$ap_radname_full,special=$reason,special_type=reason value=\"$origin_client\",special_val=\"$rs\"",$influxtime);
                break;

                case 4: //Accounting-Request

                break;

                case 5: //Accounting-Response

                break;

                case 11: //Access-Challenge

                break;

                default:
                    //echo "$reason\t$origin_client\t$timestamp\t$client\t$tt\t$ap_radname_full\n";
            }

        }
		
		echo "[+] added $datestring\n";

        $out = array();

        fclose($fh);
        $size = $currentSize;
    }
}

function sendToDB($data,$time=false)
{
	//echo "[+] $data\n"; return;
	$socket = stream_socket_client("udp://".DBIP.":".DBPORT);
	stream_socket_sendto($socket, $data.(USERADIUSTIME?' '.$time:''));
	stream_socket_shutdown($socket, STREAM_SHUT_RDWR);
}


function sanatizeStringForInflux($string)
{
    $string = trim($string);
    $string = str_replace(',','\\,',$string);
    $string = str_replace(' ','\\ ',$string);
    $string = str_replace('=','\\=',$string);
    return $string;
}

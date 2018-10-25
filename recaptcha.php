<?php

echo "\n\n\nRegister random domain and get sitekey & security key at https://www.google.com/recaptcha/admin .\n";
echo "Note that you don't have to be a domain owner, so choose random domain like randomdomain.com\n\n\n";


$domain  = readline("Domain: ");
if (strpos($domain,".") === false) {
    echo "invalid domain\n";
    exit;
}

$sitekey = readline("Site key: ");
if (strlen($sitekey) < 10) {
    echo "invalid site key!\n";
    exit;
}

$secret  = readline("Secret key: ");
if (strlen($secret) < 10) {
    echo "invalid secret key!\n";
    exit;
}

$apikey = readline("Anti-Captcha.com API key:");
if (strlen($apikey) != 32) {
    echo "invalid API key!\n";
    exit;
}

$checks = (int)readline("How many checks required? (Default value: 100):");
if ($checks == 0) {
    $checks = 100;
}

$threads = (int)readline("How many threads? (Default value: 10):");
if ($threads == 0) {
    $threads = 10;
}

//we'll store thread results in file
file_put_contents("results.txt", "");

$checksPerThread = $checks/$maxThreads;

$childPids = [];

for ($i = 0;$i < $threads;$i++) {
    $pid = pcntl_fork();
    if ($pid == 0) {
        
        for ($l = 0;$l<$checksPerThread;$l++) {
            runCheck("Thread #$i", $domain, $sitekey, $secret, $apikey);
            countResults();
        }
        exit;
    }
    $childPids[] = $pid;
}

//parent process waiting
while (count($childPids)>0) {
    
    foreach ($childPids as $key=>$pid) {
        $res = pcntl_waitpid($pid, $status, WNOHANG);
        
        // If the process has already exited
        if($res == -1 || $res > 0)
            unset($childPids[$key]);
        sleep(1);
    }
    
}
echo "CHECK COMPLETE! Final results:\n";
countResults();

function countResults() {
    $results        =   file_get_contents("results.txt");
    $success        =   substr_count($results, "SUCCESS");
    $fail           =   substr_count($results, "FAIL");
    $total          =   $success+$fail;
    if ($total > 0) {
        $successPerc = round(($success / $total * 100), 2);
        echo "\e[0;32mSuccessful results: $success, failed: $fail, total: $total. That's $successPerc% success rate.\e[0m\n";
    }
}

function runCheck($threadNum, $domain, $sitekey, $secret, $apikey) {
    $createTaskJSON = array(
        "clientKey" =>  $apikey,
        "task"      =>  array(
            "type"          =>  "NoCaptchaTaskProxyless",
            "websiteURL"    =>  "http://".$domain."/",
            "websiteKey"    =>  $sitekey
        )
    );
    echo "$threadNum: creating new task\n";
    $request = antiRequest("createTask", $createTaskJSON);
    
    if ($request["errorId"] != 0) {
        echo "$threadNum: API error at createTask: $request[errorCode] : $request[errorDescription]\n";
        exit;
    } else {
        $taskId = $request["taskId"];
        echo "$threadNum: created task with taskId: $taskId\n";
        $time = 300;
        sleep(10);
        while ($time > 0) {
            echo "$threadNum: checking task $taskId\n";
            $checkTaskJSON = array(
                "clientKey" =>  $apikey,
                "taskId"    =>  $taskId
            );
            $check = antiRequest("getTaskResult", $checkTaskJSON);
            if ($check["errorId"] != 0) {
                echo "$threadNum: API error at getTaskResult: $request[errorCode] : $request[errorDescription]\n";
                exit;
            } else {
                
                if ($check["status"] == "processing") {
                    echo "$threadNum: taskId $taskId still processing\n";
                    sleep(5);
                }
                if ($check["status"] == "ready") {
                    
                    echo "$threadNum: taskId $taskId ready, checking...\n";
                    if (siteVerify($secret, $check["solution"]["gRecaptchaResponse"])) {
                        echo "$threadNum: taskId siteverify result: CORRECT\n";
                        logResult($taskId, "SUCCESS");
                    } else {
                        echo "$threadNum: taskId siteverify result: INCORRECT\n";
                        logResult($taskId, "FAIL");
                    }
                    $time = 0;
                }
            }
            $time--;
        }
    }
}

function siteVerify($secret, $gResponse) {
    $ch = curl_init();
    curl_setopt($ch,CURLOPT_URL,"https://www.google.com/recaptcha/api/siteverify");
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch,CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch,CURLOPT_POSTFIELDS,array(
        "secret"   => $secret,
        "response" => $gResponse
    ));
    curl_setopt($ch,CURLOPT_TIMEOUT,30);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,30);
    $result =curl_exec($ch);
    $curlError = curl_error($ch);
    if ($curlError != "") {
        echo "\nNetwork error while connecting to siteverify: $curlError\n";
        return false;
    }
    curl_close($ch);
    $decoded = json_decode($result, true);
    if ($decoded["success"] == true) {
        return true;
    } else {
        return false;
    }
}

function antiRequest($methodName, $postData) {
    $ch = curl_init();
    curl_setopt($ch,CURLOPT_URL,"https://api.anti-captcha.com/$methodName");
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch,CURLOPT_ENCODING,"gzip,deflate");
    curl_setopt($ch,CURLOPT_CUSTOMREQUEST, "POST");
    $postDataEncoded = json_encode($postData);
    curl_setopt($ch,CURLOPT_POSTFIELDS,$postDataEncoded);
    curl_setopt($ch,CURLOPT_HTTPHEADER, array(
        'Content-Type: application/json; charset=utf-8',
        'Accept: application/json',
        'Content-Length: ' . strlen($postDataEncoded)
    ));
    curl_setopt($ch,CURLOPT_TIMEOUT,30);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,30);
    $result =curl_exec($ch);
    $curlError = curl_error($ch);
    if ($curlError != "") {
        echo "\nNetwork error while connecting to API: $curlError\n";
        return false;
    }
    curl_close($ch);
    return json_decode($result, true);
}

function logResult($taskId, $result) {
    $fp = fopen("results.txt", "a");
    fputs($fp, date("Y-m-d H:i:s")."\t".$taskId."\t".$result."\n");
    fclose($fp);
}
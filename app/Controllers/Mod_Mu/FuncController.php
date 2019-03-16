<?php

namespace App\Controllers\Mod_Mu;

use App\Models\DetectRule;
use App\Models\Relay;
use App\Models\BlockIp;
use App\Models\UnblockIp;
use App\Models\Speedtest;
use App\Models\Node;
use App\Models\Auto;
use App\Controllers\BaseController;
use App\Utils\Tools;
use App\Utils\Helper;

class FuncController extends BaseController
{
    public function ping($request, $response, $args)
    {
        $res = [
            "ret" => 1,
            "data" => 'pong'
        ];
        return $this->echoJson($response, $res);
    }



    /**
     *  根据gfwlist生成用户禁止访问规则，防止用户访问中国禁止访问的地址
     * @param $request
     * @param $response
     * @param $args
     * @return string
     */
    public function getDetectFromGfwlist($reqMd5,&$outMd5){
        $path=__DIR__.'/../../../';
        $rulelist=file_get_contents($path.'/decode.txt');
        $gfwlist = explode("\n", $rulelist);
        $md5=md5($rulelist);
        $rules=array();
        $tempRule=[];
        if (empty($reqMd5) || $reqMd5 != $md5) {
            $index=20000;
            foreach ($gfwlist as $item){
                if (!empty($regex=trim($item))) {
                    $isDetect=false;
                    $op=false;
                    if (Tools::startWith($item,'||')) {
                        //|| 标记，如 ||example.com 则 http://example.com 、https://example.com 、 ftp://example.com 等地址均满足条件
                        $isDetect=true;
                        $item=str_replace('||','match_',$item);
                        $op=true;
                    }else if (Tools::startWith($item,'@@')){
                        //例外

                    }else if (Tools::startWith($item,'|')){
                        //匹配开始
                        $isDetect=true;
                        $item=str_replace('|','match_',$item);
                        $op=true;
                    }else if (Tools::endWith($item,'|')){
                        //匹配结束
                        $isDetect=true;
                        $item=str_replace('|','',$item);
                        $item='match_'.$item;
                        $op=true;
                    }else if (Tools::startWith($item,'/^')){
                        //正则
                        $isDetect=true;
                    }else if(Tools::startWith($item,'!')){
                        //注释
                    }else{
                        $op=true;
                        $isDetect=true;
                        $item='match_'.$item;
                    }

                    if ($isDetect && $op) {
                        // 去除uri,只要域名
                        $i=strripos($item,'.');
                        if ($i>0) {
                            $lastStr=substr($item,$i,strlen($item));//eg:   .com\/abc\/def
                            $startStr=substr($item,0,$i);//eg: a.b.c
                            $b=strpos($lastStr,'/');
                            if ($b>0) {
                                $middleStr=substr($lastStr,0,strpos($lastStr,'/'));//eg: .com
                                $item=$startStr.$middleStr;
                            }
                        }

                    }

                    if ($isDetect) {
                        $tempRule[]=$item;
                    }

                }
            }

            $tempRule=array_unique($tempRule);
            foreach ($tempRule as $item) {
                $rule=new DetectRule();
                $rule->id=$index;
                $index++;
                $rule->regex=$item;
                $rule->type=1;
                $rules[]=$rule;
            }
            $outMd5=$md5;
        }
        return $rules;

    }
    /**
     *  根据gfwlist生成用户禁止访问规则，防止用户访问中国禁止访问的地址
     * @param $request
     * @param $response
     * @param $args
     * @return string
     */
    public function getDetectFromGfwlist2($reqMd5,&$outMd5){
        $path=__DIR__.'/../../../';
        $regexs=file_get_contents($path.'/gfw.url_regex.lst');
        $md5=md5($regexs);
        if (empty($reqMd5) || $reqMd5 != $md5) {
            $regexs = explode("\n", $regexs);
            $index=20000;
            $a=0;
            $rules=array();
            //删除uri,去除重复正则，精简列表
            foreach ($regexs as &$regex) {
                //eg :    a.b.c.com\/abc\/def
                $i=strripos($regex,'.');
                if ($i>0) {
                    $lastStr=substr($regex,$i,strlen($regex));//eg:   .com\/abc\/def
                    $startStr=substr($regex,0,$i);//eg: a.b.c
                    $b=strpos($lastStr,'\/');
                    if ($b>0) {
                        $middleStr=substr($lastStr,0,strpos($lastStr,'\/'));//eg: .com
                        $regex=$startStr.$middleStr;
//                        var_dump([$startStr,$middleStr,$lastStr]);
                    }
                }
                /*$a++;
                if ($a>100) {
                    break;
                }*/
            }
            unset($regex);
//            return [];
            //去重
            $regexs=array_unique($regexs);


            //转审计规则
            foreach ($regexs as $regex) {
                if (!empty($regex=trim($regex))) {
                    $rule=new DetectRule();
                    $rule->id=$index;
                    $index++;
                    $rule->regex=$regex;
                    $rule->type=1;
                    $rules[]=$rule;
                }
            }
            $outMd5=$md5;
            return $rules;
        }else{
            return null;
        }
    }

    public function get_detect_logs($request, $response, $args)
    {
        $key = Helper::getMuKeyFromReq($request);
        $md5="";
        if (strpos($key, 'noDetect') === 0) {
            $rules=array();
        }else{
            $rules = DetectRule::all();
            $req=$request->getQueryParams();
            $gfwList=self::getDetectFromGfwlist(empty($req['gfwlistmd5'])?null:$req['gfwlistmd5'],$md5);
            $rules=$rules->merge($gfwList);
        }
        $res = [
            "ret" => 1,
            "data" => $rules
        ];
        return $this->echoJson($response, $res);
    }

    public function get_relay_rules($request, $response, $args)
    {
        $params = $request->getQueryParams();
        $node_id = $params['node_id'];
		if($node_id=='0'){
			$node = Node::where("node_ip",$_SERVER["REMOTE_ADDR"])->first();
			$node_id=$node->id;
		}
        $rules = Relay::Where('source_node_id', $node_id)->get();

        $res = [
            "ret" => 1,
            "data" => $rules
        ];
        return $this->echoJson($response, $res);
    }

    public function get_blockip($request, $response, $args)
    {
        $block_ips = BlockIp::Where('datetime', '>', time() - 60)->get();

        $res = [
            "ret" => 1,
            "data" => $block_ips
        ];
        return $this->echoJson($response, $res);
    }

    public function get_unblockip($request, $response, $args)
    {
        $unblock_ips = UnblockIp::Where('datetime', '>', time() - 60)->get();

        $res = [
            "ret" => 1,
            "data" => $unblock_ips
        ];
        return $this->echoJson($response, $res);
    }

    public function addBlockIp($request, $response, $args)
    {
        $params = $request->getQueryParams();

        $data = $request->getParam('data');
        $node_id = $params['node_id'];
		if($node_id=='0'){
			$node = Node::where("node_ip",$_SERVER["REMOTE_ADDR"])->first();
			$node_id=$node->id;
		}
        $node = Node::find($node_id);
        if ($node == null) {
            $res = [
                "ret" => 0
            ];
            return $this->echoJson($response, $res);
        }

        if (count($data) > 0) {
            foreach ($data as $log) {
                $ip = $log['ip'];

                $exist_ip = BlockIp::where('ip', $ip)->first();
                if ($exist_ip != null) {
                    continue;
                }

                // log
                $ip_block = new BlockIp();
                $ip_block->ip = $ip;
                $ip_block->nodeid = $node_id;
                $ip_block->datetime = time();
                $ip_block->save();
            }
        }

        $res = [
            "ret" => 1,
            "data" => "ok",
        ];
        return $this->echoJson($response, $res);
    }

    public function addSpeedtest($request, $response, $args)
    {
        $params = $request->getQueryParams();

        $data = $request->getParam('data');
        $node_id = $params['node_id'];
		if($node_id=='0'){
			$node = Node::where("node_ip",$_SERVER["REMOTE_ADDR"])->first();
			$node_id=$node->id;
		}
        $node = Node::find($node_id);
        if ($node == null) {
            $res = [
                "ret" => 0
            ];
            return $this->echoJson($response, $res);
        }

        if (count($data) > 0) {
            foreach ($data as $log) {
                // log
                $speedtest_log = new Speedtest();
                $speedtest_log->telecomping = $log['telecomping'];
                $speedtest_log->telecomeupload = $log['telecomeupload'];
                $speedtest_log->telecomedownload = $log['telecomedownload'];

                $speedtest_log->unicomping = $log['unicomping'];
                $speedtest_log->unicomupload = $log['unicomupload'];
                $speedtest_log->unicomdownload = $log['unicomdownload'];

                $speedtest_log->cmccping = $log['cmccping'];
                $speedtest_log->cmccupload = $log['cmccupload'];
                $speedtest_log->cmccdownload = $log['cmccdownload'];
                $speedtest_log->nodeid = $node_id;
                $speedtest_log->datetime = time();
                $speedtest_log->save();
            }
        }

        $res = [
            "ret" => 1,
            "data" => "ok",
        ];
        return $this->echoJson($response, $res);
    }

    public function get_autoexec($request, $response, $args)
    {
        $params = $request->getQueryParams();

        $node_id = $params['node_id'];
		if($node_id=='0'){
			$node = Node::where("node_ip",$_SERVER["REMOTE_ADDR"])->first();
			$node_id=$node->id;
		}
        $node = Node::find($node_id);
        if ($node == null) {
            $res = [
                "ret" => 0
            ];
            return $this->echoJson($response, $res);
        }

        $autos_raw = Auto::where('datetime', '>', time() - 60)->where('type', '1')->get();

        $autos = array();

        foreach ($autos_raw as $auto_raw) {
            $has_exec = Auto::where('sign', $node_id.'-'.$auto_raw->id)->where('type', '2')->first();
            if ($has_exec == null) {
                array_push($autos, $auto_raw);
            }
        }

        $res = [
            "ret" => 1,
            "data" => $autos,
        ];
        return $this->echoJson($response, $res);
    }

    public function addAutoexec($request, $response, $args)
    {
        $params = $request->getQueryParams();

        $data = $request->getParam('data');
        $node_id = $params['node_id'];
		if($node_id=='0'){
			$node = Node::where("node_ip",$_SERVER["REMOTE_ADDR"])->first();
			$node_id=$node->id;
		}
        $node = Node::find($node_id);
        if ($node == null) {
            $res = [
                "ret" => 0
            ];
            return $this->echoJson($response, $res);
        }

        if (count($data) > 0) {
            foreach ($data as $log) {
                // log
                $auto_log = new Auto();
                $auto_log->value = $log['value'];
                $auto_log->sign = $log['sign'];
                $auto_log->type = $log['type'];
                $auto_log->datetime = time();
                $auto_log->save();
            }
        }

        $res = [
            "ret" => 1,
            "data" => "ok",
        ];
        return $this->echoJson($response, $res);
    }
}

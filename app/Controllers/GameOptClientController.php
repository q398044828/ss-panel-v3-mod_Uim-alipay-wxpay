<?php
/**
 * Created by IntelliJ IDEA.
 * User: xinba
 * Date: 2019/3/30
 * Time: 16:31
 */

namespace App\Controllers;

use App\Models\InviteCode;
use App\Services\Config;
use App\Utils\Check;
use App\Utils\Tools;
use App\Utils\Radius;
use voku\helper\AntiXSS;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

use App\Utils\Hash;
use App\Utils\Da;
use App\Services\Auth;
use App\Services\Mail;
use App\Models\User;
use App\Models\LoginIp;
use App\Models\EmailVerify;
use App\Utils\Duoshuo;
use App\Utils\GA;
use App\Utils\Wecenter;
use App\Utils\Geetest;
use App\Utils\TelegramSessionManager;


/**
 *  AuthController
 */
class GameOptClientController extends BaseController{

    public function login($request, $response, $args)
    {
        // $data = $request->post('sdf');
        $email = $request->getParam('email');
        $email = trim($email);
        $email = strtolower($email);
        $passwd = $request->getParam('passwd');

        $ret=[];
        if (Config::get('enable_geetest_login') == 'true') {
            $ret = Geetest::verify($request->getParam('geetest_challenge'), $request->getParam('geetest_validate'), $request->getParam('geetest_seccode'));
            if (!$ret) {
                $res['ret'] = 0;
                $res['msg'] = "系统无法接受您的验证结果，请刷新页面后重试。";
                return $response->withJson($res);
            }
        }

        // Handle Login
        $user = User::where('email', '=', $email)->first();
        if ($user == null) {
            $rs['ret'] = 0;
            $rs['msg'] = "邮箱或者密码错误";
            return $response->withJson($rs);
        }

        if (!Hash::checkPassword($user->pass, $passwd)) {
            $rs['ret'] = 0;
            $rs['msg'] = "邮箱或者密码错误.";


            $loginip = new LoginIp();
            $loginip->ip = $_SERVER["REMOTE_ADDR"];
            $loginip->userid = $user->id;
            $loginip->datetime = time();
            $loginip->type = 1;
            $loginip->save();

            return $response->withJson($rs);
        }
        // @todo
        $time = 3600 * 24 * 30;  //网游加速器客户端登陆有效时长为1个月
        $time = $time * 30;



        Auth::login($user->id, $time);
        $rs['ret'] = 1;
        $rs['msg'] = "登录成功";

        $loginip = new LoginIp();
        $loginip->ip = $_SERVER["REMOTE_ADDR"];
        $loginip->userid = $user->id;
        $loginip->datetime = time();
        $loginip->type = 0;
        $loginip->save();

        Wecenter::add($user, $passwd);
        Wecenter::Login($user, $passwd, $time);

        return $response->withJson($rs);
    }
}
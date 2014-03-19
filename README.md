#User_Session Class
##Requirement 
- libmcrypt
##install

```
phpize
./configure
make
make install
```

## Runtime Configure
- ledu.iv    //DES CBC iv,default AAAAAAAA  
- ledu.cookie_name  // cookie name  ldauth
- ledu.key  //DES CBC key default BBBBBBBB

##usage
```
ldclass::__construct
ldclass::getUid
ldclass::getUserName
ldclass::isLogin
ldclass::setLogin(uid, username[,expires])
ldclass::setLoginout
```

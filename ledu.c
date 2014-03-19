/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: lietdai@gmail.com                                            |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include <string.h>
#include <time.h>
#if HAVE_LIBMCRYPT

#include "php_ini.h"
#include "ext/standard/info.h"
#include "mcrypt.h"
#include "ext/standard/md5.h"

//#include "php_global.h"
#include "TSRM.h"
#include "php_ledu.h"
ZEND_DECLARE_MODULE_GLOBALS(ledu);

#define MCRYPT_OPEN_MODULE_FAILED "Module initialization failed"
#define MCRYPT_IV_WRONG_SIZE "The IV parameter must be as long as the blocksize"
#define MCRYPT_ENCRYPT 0
#define MCRYPT_DECRYPT 1

/* this is read-only, so it's ok */
static char hexconvtab[] = "0123456789abcdef";

/* {{{ php_bin2hex
 */
static char *php_bin2hex(const unsigned char *old, const size_t oldlen, size_t *newlen)
{
	register unsigned char *result = NULL;
	size_t i, j;

	result = (unsigned char *) safe_emalloc(oldlen, 2 * sizeof(char), 1);

	for (i = j = 0; i < oldlen; i++) {
		result[j++] = hexconvtab[old[i] >> 4];
		result[j++] = hexconvtab[old[i] & 15];
	}
	result[j] = '\0';

	if (newlen)
		*newlen = oldlen * 2 * sizeof(char);

	return (char *)result;
}
/* }}} */

/* {{{ php_hex2bin
 */
static char *php_hex2bin(const unsigned char *old, const size_t oldlen, size_t *newlen)
{
	size_t target_length = oldlen >> 1;
	register unsigned char *str = (unsigned char *)safe_emalloc(target_length, sizeof(char), 1);
	size_t i, j;
	for (i = j = 0; i < target_length; i++) {
		char c = old[j++];
		if (c >= '0' && c <= '9') {
			str[i] = (c - '0') << 4;
		} else if (c >= 'a' && c <= 'f') {
			str[i] = (c - 'a' + 10) << 4;
		} else if (c >= 'A' && c <= 'F') {
			str[i] = (c - 'A' + 10) << 4;
		} else {
			efree(str);
			return NULL;
		}
		c = old[j++];
		if (c >= '0' && c <= '9') {
			str[i] |= c - '0';
		} else if (c >= 'a' && c <= 'f') {
			str[i] |= c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			str[i] |= c - 'A' + 10;
		} else {
			efree(str);
			return NULL;
		}
	}
	str[target_length] = '\0';

	if (newlen)
		*newlen = target_length;

	return (char *)str;
}
/* }}} */


static char* php_mcrypt_do_crypt(char* cipher, const char *key, int key_len, const char *data, int data_len, char *mode, const char *iv, int iv_len, int dencrypt TSRMLS_DC) /* {{{ */
{

	int block_size, max_key_length, use_key_length, i, count, iv_size;
	unsigned long int data_size;
	int *key_length_sizes;
	char *key_s = NULL, *iv_s;
	char *data_s;
	MCRYPT td;

	//MCRYPT_GET_INI
	td = mcrypt_module_open(cipher, NULL, mode, NULL);
	if (td == MCRYPT_FAILED) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, MCRYPT_OPEN_MODULE_FAILED);
		return NULL;
	}
	/* Checking for key-length */
	max_key_length = mcrypt_enc_get_key_size(td);
	if (key_len > max_key_length) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Size of key is too large for this algorithm");
	}
	key_length_sizes = mcrypt_enc_get_supported_key_sizes(td, &count);
	if (count == 0 && key_length_sizes == NULL) { /* all lengths 1 - k_l_s = OK */
		use_key_length = key_len;
		key_s = emalloc(use_key_length);
		memset(key_s, 0, use_key_length);
		memcpy(key_s, key, use_key_length);
	} else if (count == 1) {  /* only m_k_l = OK */
		key_s = emalloc(key_length_sizes[0]);
		memset(key_s, 0, key_length_sizes[0]);
		memcpy(key_s, key, MIN(key_len, key_length_sizes[0]));
		use_key_length = key_length_sizes[0];
	} else { /* dertermine smallest supported key > length of requested key */
		use_key_length = max_key_length; /* start with max key length */
		for (i = 0; i < count; i++) {
			if (key_length_sizes[i] >= key_len && 
				key_length_sizes[i] < use_key_length)
			{
				use_key_length = key_length_sizes[i];
			}
		}
		key_s = emalloc(use_key_length);
		memset(key_s, 0, use_key_length);
		memcpy(key_s, key, MIN(key_len, use_key_length));
	}
	mcrypt_free (key_length_sizes);
	
	/* Check IV */
	iv_s = NULL;
	iv_size = mcrypt_enc_get_iv_size (td);
	

	/* IV is required */
	if (mcrypt_enc_mode_has_iv(td) == 1) {
			if (iv_size != iv_len) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, MCRYPT_IV_WRONG_SIZE);
			} else {
				iv_s = emalloc(iv_size + 1);
				memcpy(iv_s, iv, iv_size);
			}
	}
	/* Check blocksize */
	if (mcrypt_enc_is_block_mode(td) == 1) { /* It's a block algorithm */
		block_size = mcrypt_enc_get_block_size(td);
		data_size = (((data_len - 1) / block_size) + 1) * block_size;
		data_s = emalloc(data_size);
		memset(data_s, 0, data_size);
		memcpy(data_s, data, data_len);
	} else { /* It's not a block algorithm */
		data_size = data_len;
		data_s = emalloc(data_size);
		memset(data_s, 0, data_size);
		memcpy(data_s, data, data_len);
	}
	if (mcrypt_generic_init(td, key_s, use_key_length, iv_s) < 0) {
		php_error_docref(NULL TSRMLS_CC, E_RECOVERABLE_ERROR, "Mcrypt initialisation failed");
		return NULL;
	}
	if (dencrypt == MCRYPT_ENCRYPT) {
		mcrypt_generic(td, data_s, data_size);
	} else {
		mdecrypt_generic(td, data_s, data_size);
	}
    return data_s;
	//RETVAL_STRINGL(data_s, data_size, 1);

	/* freeing vars */
	mcrypt_generic_end(td);
	if (key_s != NULL) {
		efree (key_s);
	}
	if (iv_s != NULL) {
		efree (iv_s);
	}
	efree (data_s);
}
/* }}} */


zend_class_entry *request;
/* If you declare any globals in php_ledu.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(ledu)
*/

/* True global resources - no need for thread safety here */
static int le_ledu;

/* {{{ ledu_functions[]
 *
 * Every user visible function must have an entry in ledu_functions[].
 */
const zend_function_entry ledu_functions[] = {
	PHP_FE_END	/* Must be the last line in ledu_functions[] */
};

/* {{{ PHP_INI
 */

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("ledu.iv", "AAAAAAAA", PHP_INI_ALL, OnUpdateLong, iv, zend_ledu_globals, ledu_globals)
    STD_PHP_INI_ENTRY("ledu.key", "BBBBBBBB", PHP_INI_ALL, OnUpdateLong, key, zend_ledu_globals, ledu_globals)
    STD_PHP_INI_ENTRY("ledu.cookie_name", "ldauth", PHP_INI_ALL, OnUpdateString, cookie_name, zend_ledu_globals, ledu_globals)
PHP_INI_END()

/* }}} */



PHP_METHOD(ldclass, __construct){
    zval *name; 
    MAKE_STD_ZVAL(name);
    ZVAL_STRING(name, INI_STR("ledu.cookie_name"), 1);    
    zend_class_entry *ce;
    int len;
    zval *params = NULL;
    zval **ppzval = NULL;
    char *auth,*auth2;
    size_t newlen;
    ce = Z_OBJCE_P(getThis());
    params = PG(http_globals)[TRACK_VARS_COOKIE];
    if (params && Z_TYPE_P(params) == IS_ARRAY)
        {
            if (zend_hash_find(Z_ARRVAL_P(params), Z_STRVAL_P(name), Z_STRLEN_P(name)+1, (void **)&ppzval) == SUCCESS )
                {
                    if(Z_TYPE_PP(ppzval) != IS_STRING || !Z_STRVAL_PP(ppzval)){
                        return ;
                    }
                    php_strtolower(Z_STRVAL_PP(ppzval),Z_STRLEN_PP(ppzval));
                    auth = php_hex2bin((unsigned char *)Z_STRVAL_PP(ppzval),Z_STRLEN_PP(ppzval),&newlen);
                    if(auth == NULL){
                        return;
                    }
                    auth2 = php_mcrypt_do_crypt(MCRYPT_DES,INI_STR("ledu.key"),strlen(INI_STR("ledu.key")),auth,strlen(auth),"cbc",INI_STR("ledu.iv"),strlen(INI_STR("ledu.iv")),1 TSRMLS_CC);
                    if(auth2 == NULL){
                        return;
                    }
                    /*@fix me 加密str完整性验证*/
                    const char *delim = "\t";
                    int count = 0;
                    char *tmp;
                    tmp = strtok(auth2,delim);
                    while(tmp != NULL){
                        if(0 == count){
                            zend_update_property_string(ce, getThis(), ZEND_STRL("uid"), tmp TSRMLS_CC);
                        }else if(1 == count){
                            zend_update_property_string(ce, getThis(), ZEND_STRL("username"), tmp TSRMLS_CC);
                        }
                        tmp = strtok(NULL, delim);
                        count++;                        
                    }
                }
        }
}


PHP_METHOD(ldclass, getUid){
    zval *uid = NULL;
    zend_class_entry *ce;
    ce = Z_OBJCE_P(getThis());
    uid = zend_read_property(ce, getThis(), "uid", sizeof("uid")-1, 0 TSRMLS_CC);
    RETURN_ZVAL(uid,1,0);
}

PHP_METHOD(ldclass, getUserName){
    zval *username = NULL;
    zend_class_entry *ce;
    ce = Z_OBJCE_P(getThis());
    username = zend_read_property(ce, getThis(), ZEND_STRL("username"), 0 TSRMLS_CC);
    RETURN_ZVAL(username,1,0);
}

PHP_METHOD(ldclass, isLogin){
    zval *uid;
    zend_class_entry *ce;
    ce = Z_OBJCE_P(getThis());
    uid = zend_read_property(ce, getThis(), ZEND_STRL("uid"), 0 TSRMLS_CC);
    if(Z_TYPE_P(uid) == IS_NULL){
        RETURN_FALSE
    }
    RETURN_TRUE;
}

PHP_METHOD(ldclass, setLogin){
    zval **ppzval,
        *ua,*domain,*params,*cookie_value,*cookie_name;
    zend_bool secure = 0, httponly = 0;
    zend_class_entry *ce;
    char str[100],        
        *auth,*uid,*username,
        md5ua[33];
    uint uid_len,username_len;
    unsigned char digest[16];
    time_t timeval;
    PHP_MD5_CTX context;
    size_t newlen;
    long expires = 0;
    MAKE_STD_ZVAL(cookie_name);
    ZVAL_STRING(cookie_name, INI_STR("ledu.cookie_name"), 1);
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l",&uid, &uid_len, &username, &username_len, &expires) == FAILURE){
        return;
    }    
    ce = Z_OBJCE_P(getThis());
    params = PG(http_globals)[TRACK_VARS_SERVER];
    if(zend_hash_find(Z_ARRVAL_P(params), ZEND_STRS("HTTP_USER_AGENT"), (void **)&ppzval ) == SUCCESS)
        {                   
            ua = *ppzval;
        }
    if(zend_hash_find(Z_ARRVAL_P(params), ZEND_STRS("SERVER_NAME"), (void **)&ppzval ) == SUCCESS)
        {                   
            domain = *ppzval;
        }    
    md5ua[0] = '\0';
    PHP_MD5Init(&context);
    PHP_MD5Update(&context,Z_STRVAL_P(ua),Z_STRLEN_P(ua));
    PHP_MD5Final(digest, &context);
    make_digest_ex(md5ua, digest, 16);
    (void)time(&timeval);
    sprintf(str,"%s\t%s\t%s\t%ld",uid,username,md5ua,timeval);
    auth = php_mcrypt_do_crypt(MCRYPT_DES,INI_STR("ledu.key"),strlen(INI_STR("ledu.key")),str,strlen(str),"cbc",INI_STR("ledu.iv"),strlen(INI_STR("ledu.iv")),0 TSRMLS_CC);
    auth = php_bin2hex(auth, strlen(auth), &newlen);
    MAKE_STD_ZVAL(cookie_value);
    ZVAL_STRING(cookie_value, auth, 1);
    php_strtoupper(Z_STRVAL_P(cookie_value),Z_STRLEN_P(cookie_value));
    php_bin2hex(Z_STRVAL_P(cookie_value), Z_STRLEN_P(cookie_value), &newlen);
    if ( php_setcookie(Z_STRVAL_P(cookie_name), Z_STRLEN_P(cookie_name), Z_STRVAL_P(cookie_value), Z_STRLEN_P(cookie_value), expires, "/", sizeof("/") -1, Z_STRVAL_P(domain), Z_STRLEN_P(domain), secure, 1, httponly TSRMLS_CC ) == SUCCESS){
        RETVAL_TRUE;
    }else{
        RETVAL_FALSE;
    }
}

PHP_METHOD(ldclass, setLoginout){
    zval *cookie_name, *domain = NULL, *params = NULL,
        **ppzval;
    zend_bool secure = 0, httponly = 0;
    MAKE_STD_ZVAL(cookie_name);
    ZVAL_STRING(cookie_name, INI_STR("ledu.cookie_name"), 1);
    params = PG(http_globals)[TRACK_VARS_SERVER];
    if(zend_hash_find(Z_ARRVAL_P(params), ZEND_STRS("SERVER_NAME"), (void **)&ppzval ) == SUCCESS)
        {                   
            domain = *ppzval;
        }
    if ( php_setcookie(Z_STRVAL_P(cookie_name), Z_STRLEN_P(cookie_name),NULL, 0, -1, "/", sizeof("/") -1, Z_STRVAL_P(domain), Z_STRLEN_P(domain), secure, 1, httponly TSRMLS_CC ) == SUCCESS){
        RETVAL_TRUE;
    }else{
        RETVAL_FALSE;
    }
    RETURN_TRUE;
}


const zend_function_entry myclass_method[] = {
    PHP_ME(ldclass, __construct, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(ldclass, getUid, NULL, ZEND_ACC_PUBLIC )
    PHP_ME(ldclass, getUserName, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(ldclass, isLogin, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(ldclass, setLogin, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(ldclass, setLoginout, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
/* }}} */


/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(ledu)
{
	/* If you have INI entries, uncomment these lines        */
	REGISTER_INI_ENTRIES();
	/**/
    zend_class_entry ce;
    INIT_CLASS_ENTRY(ce, "ldclass",myclass_method);
    request = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(request, "uid",
                               strlen("uid"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(request, "username",
                               strlen("username"), ZEND_ACC_PRIVATE TSRMLS_CC);
    
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(ledu)
{
	/* uncomment this line if you have INI entries*/
	UNREGISTER_INI_ENTRIES();
	/**/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(ledu)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(ledu)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(ledu)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "ledu support", "enabled");
    php_info_print_table_row(2, "author", "liet");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini*/
	DISPLAY_INI_ENTRIES();
	/**/
}
/* }}} */



#ifdef COMPILE_DL_LEDU
ZEND_GET_MODULE(ledu)
#endif

/**{{{ module depends
 */
#if ZEND_MODULE_API_NO >= 20050922
zend_module_dep ledu_deps[] = {
    ZEND_MOD_REQUIRED("mcrypt")
    {NULL, NULL, NULL}
};
#endif


/* {{{ ledu_module_entry
 */
zend_module_entry ledu_module_entry = {
#if ZEND_MODULE_API_NO >= 20050922
    STANDARD_MODULE_HEADER_EX, NULL,
    ledu_deps,
#else
    STANDARD_MODULE_HEADER,
#endif
	"ledu",
	ledu_functions,
	PHP_MINIT(ledu),
	PHP_MSHUTDOWN(ledu),
	PHP_RINIT(ledu),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(ledu),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(ledu),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_LEDU_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */



#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

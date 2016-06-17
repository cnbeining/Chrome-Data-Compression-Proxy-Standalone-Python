# Chrome-Data-Compression-Proxy-Standalone-Python
A Python wrapper of Chrome DCP. 

Inspired by datacompressionproxy(https://code.google.com/p/datacompressionproxy/), and Sogou proxy(http://xiaoxia.org/2011/11/14/update-sogou-proxy-program-with-https-support/).

Details of Chrome DCP:

https://developer.chrome.com/multidevice/data-compression

https://support.google.com/chrome/answer/3517349?hl=en

Known Limits
------

- **DOES NOT WORK WITH HTTPS**: Google does not pass HTTPS traffic with DCP. The only way to do that is do a MITM by yourself, which is obviously terrible. You can use the PAC file to redirect HTTPS traffic to DIRECT though.
- Only works with **Python 2.7.9+**: I need ```SSLContext```. Especially when you are using OSX, you need to get the latest Python by yourself. More about it: https://stackoverflow.com/questions/28228214/ssl-module-object-has-no-attribute-sslcontext 
- Could be not working with large files.
- Your network admin can FORCE you to use the HTTP version of this proxy, so they can look into your traffic. I am giving an warning if that happens, but this code is **NOT** tested to make sure it is safe from attacks including but not limited to SSLStrip. Use at your own risk.
- As Google Global Cache can be located in your ISP's data center, you should expect **NO PRIVACY** of your traffic with this proxy.

Usage
------

    python proxy.py (-p 8080) (-m HTTPS) (-i 127.0.0.1)
    
    -p: Default: 8080
        The port this proxy is listening on.
    
    -m: Default: HTTPS
        The mode, HTTPS or HTTP. If not set, the proxy will try HTTPS, and fall back to HTTP should required.
    
    -i: Default: ''
        The IP address this proxy is listening on.


Requirement
------

- Python 2.7.9+
- ```ssl``` package, as in openssl
- Highly recommended: Proxy SwitchyOmega (https://github.com/FelisCatus/SwitchyOmega) or alternatives.

Author
-----
Beining, http://www.cnbeining.com/ .

The header algorithm comes from datacompressionproxy, https://code.google.com/p/datacompressionproxy/ , License: Apache 2.0. Author: jerzyglowacki, http://www.niute.ch/ .

The main part comes from Sogou Proxy, http://xiaoxia.org/2011/11/14/update-sogou-proxy-program-with-https-support/ . Author: Xiaoxia, http://xiaoxia.org .

License
-----
GPLv2.

This program is provided **as is**, with absolutely no warranty.

History
----
0.0.3: Fix PAC problem.

0.0.2: Add PAC file to use with plugins to redirect non-HTTP traffic so you won't feel any lag.

0.0.1: The very start
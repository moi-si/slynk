var domains = {
  "google.com": 1,
  "google.com.hk": 1,
  "gstatic.com": 1,
  "googleapis.com": 1,
  "googleusercontent.com": 1,
  "goo.gl": 1,
  "translate.goog": 1,
  "android.com": 1,
  "ai.dev": 1,
  "blogger.com": 1,
  "blogspot.com": 1,
  "chrome.com": 1,
  "chromium.org": 1,
  "golang.org": 1,
  "youtube.com": 1,
  "youtube-nocookie.com": 1,
  "gvt1.com": 1,
  "googlevideo.com": 1
};

var shexps = {
  "*://*.google/*": 1,
  "*://youtu.be/*": 1,
  "*://*.ytimg.com/*": 1,
  "*://*.ggpht.com/*": 1
};

var proxy = "PROXY 127.0.0.1:{{port}};";

var direct = 'DIRECT;';

var hasOwnProperty = Object.prototype.hasOwnProperty;

function shExpMatchs(str, shexps) {
    for (var shexp in shexps) {
        if (shExpMatch(str, shexp)) {
            return true;
        }
    }
    return false;
}

function FindProxyForURL(url, host) {
    var suffix;
    var pos = host.lastIndexOf('.');
    pos = host.lastIndexOf('.', pos - 1);
    while(1) {
        if (pos <= 0) {
            if (hasOwnProperty.call(domains, host)) {
                return proxy;
            } else if (shExpMatchs(url, shexps)) {
                return proxy;
            } else {
                return direct;
            }
        }
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domains, suffix)) {
            return proxy;
        }
        pos = host.lastIndexOf('.', pos - 1);
    }
}
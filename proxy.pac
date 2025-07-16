var domains = {
  "google.com": 1,
  "google.com.hk": 1,
  "google.dev": 1,
  "googlesource.com": 1,
  "gstatic.com": 1,
  "googleapis.com": 1,
  "googleusercontent.com": 1,
  "goo.gl": 1,
  "translate.goog": 1,
  "withgoogle.com": 1,
  "pages.dev": 1,
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
  "googlevideo.com": 1,
  "github.com": 1,
  "github.io": 1,
  "cloudflare.com": 1,
  "cloudflare-dns.com": 1,
  "one.one.one.one": 1,
  "workers.dev": 1,
  "duckduckgo.com": 1,
  "ddg.gg": 1,
  "ddg.co": 1,
  "duck.com": 1,
  "telegram.org": 1,
  "telegram.me": 1,
  "reddit.com": 1,
  "redd.it": 1,
  "redditmedia.com": 1,
  "dropbox.com": 1,
  "facebook.com": 1,
  "fbcdn.net": 1,
  "fbsbx.com": 1,
  "x.com": 1,
  "twitter.com": 1,
  "pscp.tv": 1,
  "xcancel.com": 1,
  "discord.com": 1,
  "discord.gg": 1,
  "discordapp.com": 1,
  "medium.com": 1,
  "annas-archive.org": 1,
  "mastodon.social": 1,
  "fosstodon.org": 1,
  "good.news": 1,
  "bsky.app": 1,
  "cmx.im": 1,
  "mov.im": 1,
  "matrix.org": 1,
  "hack.chat": 1,
  "bbc.com": 1,
  "bbci.co.uk": 1,
  "nytimes.com": 1,
  "nyt.com": 1,
  "adminforge.de": 1,
  "apkmirror.com": 1,
  "uptodown.com": 1,
  "f-droid.org": 1,
  "freebrowser.org": 1,
  "freewechat.com": 1,
  "freezhihu.org": 1,
  "lsepcn.com": 1,
  "archive.org": 1,
  "archive.ph": 1,
  "archive-it.org": 1,
  "patreon.com": 1,
  "bootstrapcdn.com": 1,
  "suno.com": 1,
  "audiomack.com": 1,
  "deepl.com": 1,
  "deviantart.com" : 1,
  "novelai.net": 1,
  "flowith.io": 1,
  "twitch.tv": 1,
  "scratch.mit.edu": 1,
  "steampowered.com": 1,
  "steamcommunity.com": 1,
  "pixiv.net": 1,
  "pixiv.org": 1,
  "konachan.com": 1,
  "wallhaven.cc": 1,
  "imgur.com": 1,
  "bangumi.moe": 1,
  "nicovideo.jp": 1,
  "invidious.io": 1,
  "nadeko.net": 1,
  "wikimedia.org": 1,
  "wikipedia.org": 1,
  "wiktionary.org": 1,
  "wikiquote.org": 1,
  "wikibooks.org": 1,
  "wikisource.org": 1,
  "wikiversity.org": 1,
  "wikidata.org": 1,
  "wikifunctions.org": 1,
  "wikivoyage.org": 1,
  "anticommunism.miraheze.org": 1,
  "greasyfork.org": 1,
  "v2ex.com": 1,
  "odysee.com": 1,
  "receiveasmsonline.com": 1,
  "gravatar.com": 1,
  "rutube.ru": 1,
  "thepiratebay.org": 1,
  "archiveofourown.org": 1,
  "gfw.report": 1,
  "greatfire.org": 1,
  "ooni.org": 1,
  "proton.me": 1,
  "solana.com": 1
};

var shexps = [
  "*://*.google/*",
  "*://youtu.be/*",
  "*://*.ytimg.com/*",
  "*://*.ggpht.com/*",
  "*://*.githubassets.com/*",
  "*://*.githubusercontent.com/*",
  "*://*.cdn-telegram.org/*",
  "*://t.me/*",
  "*://*.twimg.com/*",
  "*://*.redditstatic.com/*",
  "*://indieweb.social/*",
  "*://good.news/*",
  "*://bsky.social/*",
  "*://ci-ic.org/*",
  "*://avogadr.io/*",
  "*://disk.yandex.com/*",
  "*://search.yahoo.co.jp/*",
  "*://i.pximg.net/*",
  "*://wiki.viva-la-vita.org/*"
];

var proxy = "PROXY 127.0.0.1:{{port}};";

var hasOwnProperty = Object.prototype.hasOwnProperty;

function shExpMatchs(url, shexps) {
  for (const pattern of shexps) {
    if (shExpMatch(url, pattern)) return true;
  }
  return false;
};

function FindProxyForURL(url, host) {
    var suffix;
    var pos = host.lastIndexOf('.');
    pos = host.lastIndexOf('.', pos - 1);
    while(1) {
        if (pos <= 0) {
            if (hasOwnProperty.call(domains, host)) return proxy;
            else if (shExpMatchs(url, shexps)) return proxy;
            else return direct;
        }
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domains, suffix)) return proxy;
        pos = host.lastIndexOf('.', pos - 1);
    }
}
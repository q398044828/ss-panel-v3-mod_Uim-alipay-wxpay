INSERT INTO `detect_list`( `name`, `text`, `regex`, `type`) VALUES
('屏蔽SPAM', '屏蔽SPAM', '(Subject|HELO|SMTP)', 1),
('禁止BT下載','禁止BT下載','BitTorrent protocol',1),
('禁止百度定位','禁止百度定位','(api|ps|sv|offnavi|newvector|ulog\.imap|newloc)(\.map|)\.(baidu|n\.shifen)\.com',1),
('屏蔽360','屏蔽360','(.+\.|^)(360|so)\.(cn|com)',1),
('屏蔽轮子网站','屏蔽轮子网站','(.*\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\.(org|com|net)',1),
('屏蔽迅雷','屏蔽迅雷','(.?)(xunlei|sandai|Thunder|XLLiveUD)(.)',1);

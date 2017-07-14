yaraのpcapモジュール用のテストデータとスクリプト
----

なにこれ
----
C92のK\_atcの記事で使用したyaraのpcapモジュール用のテストデータとテストスクリプトです。
pythonのラッパーコードも含みます。

data/pcap
----
### `nmap_standard_scan.pcap` 
https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=NMap+Captures.zip
のzipファイル内の同名のpcapファイルと同一です

### `wordpress-4.7.0-unauthorized-contents-injection.pcap`
Wordpress 4.7に対するContents Injection攻撃時のパケットデータです。
筆者が作成したものです。

### `dig_domains.pcap`
いくつかのドメインをDNS問い合わせ（dig）したときのパケットデータです。
筆者が作成したものです。

テストスクリプト
----
### `do-test.sh`
一括で色々テストしてくれる優れものです。pcapモジュールが組み込まれたyaraとyaraライブラリの場所は各自で修正してください。

pythonラッパーコード
----
`yara-pcap-test.py`　です。
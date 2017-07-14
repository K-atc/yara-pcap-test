import "pcap"

rule tcp_dest_ssh : wireshark tcp_port
{
    meta:
        description = "possible incomming SSH connection"
        wireshark_filter = "tcp.port == 22"
    condition:
        /* pcap.packets[5].tcp.dstport == 22 */
        for any i in (0..pcap.number_of_packets): 
        (
            pcap.packets[i].tcp.dstport == 22
        )
}

rule mirai_port : wireshark tcp_port malicious_port
{
    meta:
        description = "Mirai malware communication"
        wireshark_filter = "tcp.port == 7547"
    condition:
        for any i in (0..pcap.number_of_packets): 
        (
            pcap.packets[i].tcp.dstport == 7547 or
            pcap.packets[i].tcp.srcport == 7547
        ) 
}

rule telnet_port : wireshark tcp_port malicious_port
{
    meta:
        description = "Telnet connection"
        wireshark_filter = "telnet"
        // wireshark_filter = "tcp.port == 23 || tcp.port == 23"
    condition:
        for any i in (0..pcap.number_of_packets): 
        (
            pcap.packets[i].tcp.dstport == 23 or
            pcap.packets[i].tcp.dstport == 2323
        )
}

rule wordpress_content_injection : web wordpress
{
    meta:
        description = "unauthorized content injection vulnerability in Wordpress 4.7.0, 4.7.1"
        url = "https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html"
        impacted_application = "Wordpress"
        impacted_application_versions = "4.7.0, 4.7.1"
        wireshark_filter = "http.request.full_uri contains \"wp-json/wp/v2/posts/\""
    /*
    strings:
        $1 = /index\.php\/wp\-json\/wp\/v2\/posts[0-9]/
    */
    condition:
        pcap.check.http_request(/index\.php\/wp\-json\/wp\/v2\/posts\/[0-9]/)

        /* $1 in the following condition occurs "wrong argument" error */
        /* pcap.check.http_request($1) */

        /* 
         * This codition occurs the following syntax error:
         *      error: syntax error, unexpected _STRING_IDENTIFIER_
         * so I implemented check function
         */
         /*
        for any i in (0..pcap.number_of_packets):
        (
            pcap.packets[i].http.request.uri contains $1
        )
        */
}

rule dns_tunneling_base_n_encoding : dns tunneling base_n_encoding
{
    meta:
        description = "potential DNS Tunneling using Base-n encoding"
        status = "experimental"
    condition:
        pcap.detected.number_of_base_n_encoding > 5
}

rule dns_tunneling_hex_encoding : dns tunneling hex_encoding
{
    meta:
        description = "potential DNS Tunneling using Hex encoding"
        status = "experimental"
    condition:
        pcap.detected.number_of_hex_encoding > 9
}
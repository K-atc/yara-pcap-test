import sys
import yara 

def usage():
    print("usage: %s YARA_RULE_FILE FILE" % sys.argv[0])
    exit()

if not len(sys.argv) == 3:
    usage()

YARA_RULE_FILE = sys.argv[1]
FILE = sys.argv[2]
rules = yara.compile(YARA_RULE_FILE)
matches = rules.match(FILE)
for matched_rule in matches:
    print("Matched \033[33m%s\033[m rule" % (matched_rule.rule))
    # print("\t%s" % matched_rule.meta) # for debugging
    print("\t%s" % matched_rule.meta["description"])
    if "url" in matched_rule.meta:
        print("\t%s" % matched_rule.meta["url"])
    print("\tTag: %s" % ', '.join(matched_rule.tags))
    if "web" in matched_rule.tags:
        print("\tImpacted Application: %s (ver. %s)" % (
            matched_rule.meta["impacted_application"], 
            matched_rule.meta["impacted_application_versions"]))
    elif "wireshark" in matched_rule.tags:
        pass
    if "wireshark_filter" in matched_rule.meta:
        print("\tWireshark Filter: \033[32m%s\033[m" % matched_rule.meta["wireshark_filter"])
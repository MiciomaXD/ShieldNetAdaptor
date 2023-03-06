PCAP_PATH='test_pcap/test.pcap'
NAMED_PIPE_TO_CORE='./shieldnet_ecomms_to_core'
NAMED_PIPE_TO_EXT='./shieldnet_ecomms_to_ext'
APP_NAME_CORE='ShieldNet v1.0 - core'
APP_NAME_INTERACTIVE='ShieldNet v1.0 - interactive'
#MODEL_PATH='./model/sn_final.model'
CLASSIC_SHIELD_RULES='./iptables/og_iptables_rules.txt'
CLASSIC_SHIELD_RULES_OPT='./iptables/og_iptables_rules_optional.txt'
CLASSIC_SHIELD_RULES_SYNPROXY='./iptables/og_iptables_rules_synproxy.txt'
SHIELDNET_MODEL_PATH='./model/02-10-2023_11-38-49__anova_binary_opt_sched_on_fair.model'
SCALER_PATH='./model/scaler.pkl'
CLASSIC_SHIELD_SKIP=True
EXTENDED_CLASSIC_SHIELD_SKIP=False
SYNPROXY_SHIELD_SKIP=True
REACTION_TIME_SEC=10
AT_LEAST_FWD_PKT_TO_CLASSIF=20 #training dataset fwd packets number stats are Avg: 27.29087420598992, Min: 0, Max: 309628
OLD_AFTER_SEC=4*60 #4'
JAIL_TIME_SEC=12*60*60 #12h
TCP_FLAGS_TRANSLATOR = {
                    "F": "FIN",
                    "S": "SYN",
                    "R": "RST",
                    "P": "PSH",
                    "A": "ACK",
                    "U": "URG",
                    "E": "ECE",
                    "C": "CWR",
                }
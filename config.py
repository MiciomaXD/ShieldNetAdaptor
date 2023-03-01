PCAP_PATH='test_pcap/test.pcap'
NAMED_PIPE_TO_CORE='./shieldnet_ecomms_to_core'
NAMED_PIPE_TO_EXT='./shieldnet_ecomms_to_ext'
APP_NAME_CORE='ShieldNet v1.0 - core'
APP_NAME_INTERACTIVE='ShieldNet v1.0 - interactive'
MODEL_PATH='model/sn_final.model'
CLASSIC_SHIELD_RULES='./iptables/og_iptables_rules.txt'
CLASSIC_SHIELD_RULES_OPT='./iptables/og_iptables_rules_optional.txt'
CLASSIC_SHIELD_RULES_SYNPROXY='./iptables/og_iptables_rules_synproxy.txt'
SHIELDNET_MODEL_PATH='./models/02-10-2023_11-38-49__anova_binary_opt_sched_on_fair.model'
SCALER_PATH='./model/scaler.pkl'
CLASSIC_SHIELD_SKIP=True
EXTENDED_CLASSIC_SHIELD_SKIP=False
SYNPROXY_SHIELD_SKIP=True
REACTION_TIME_SEC=10
OLD_AFTER_SEC=240
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
import json
import yaml
import sys
from jnpr.junos import Device
from jnpr.junos.utils.config import Config

# Function to get Session IDs from SRX for a give Source IP
def gET_ID(NODE, SOURCEIP):
        FLOW = NODE.rpc.get_flow_session_information(source_prefix=SOURCEIP)
        ID_LIST = list()
        for i in FLOW:
                SESSION = i.find('flow-session-information')
                for SESSION_INFO in SESSION.iter("flow-session"):
                        if SESSION_INFO.findtext('flow-information/source-address') == SOURCEIP:
                                ID_LIST.append(SESSION_INFO.findtext('session-identifier'))
        return ID_LIST


# Function to clear session using the Session Identifier
def cLEAR_ID(NODE, SOURCE):
        NODE.rpc.clear_flow_session(source_prefix=SOURCE)



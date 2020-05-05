import random

from jinja2 import Environment

from .sendmessage import *
from .splunkutils import *
from .timeutils import *
import pytest
env = Environment()


testdata_squid = [
'{{ mark }}{{ bsd }} {{ host }}  1588255249.000 328 cisco_wsa TCP_MISS/304 3806 POST http://test_web.net/users/user4.jpg Alexei_Romanov NONE/www.xxxxxxx15.com application/pkix-crl PASSTHRU_CUSTOMCAT_315-ftpnoauth.policy-CyberRange_DC_NoAuth-RFS_Transparent_Proxy_Test-DefaultGroup-ExternalDLPolicy-random_policy <IW_infr,4.5,-,"-",-,-,-,13,"236ED.exe",315,315,315,"4A1F76506",-,-,"-","-",-,-,IW_infr,"10","Spyware","-","Avc_app","acbd","Unknown","-",213.0299,1,[Local],"-","-",13,"-",315,1,"-","-"> "abcd" 526',
'{{ mark }}{{ bsd }} {{ host }}  1588255249.000 123 cisco_wsa TCP_DENIED/403 0 HEAD http://test_web.net/users/user5.jpg Tom_Lawrence DEFAULT_PARENT/www.xxxxxxx10.com application/x-dosexec PASSTHRU_WBRS_178-Decrypt_Admin_Access-CyberRange_DC_NoAuth-NONE-random_policy-ExternalDLPolicy-DIRECT <IW_swup,9.2,-,"-",-,-,-,-,"-",-,-,-,"-",-,-,"-","-",-,-,IW_swup,-,"-","-","Unknown","Unknown","-","-",0.00,0,-,"-","-",-,"-",-,-,"-","-"> - ',
'{{ mark }}{{ bsd }} {{ host }}  1588255249.000 111 cisco_wsa TCP_DENIED/407 0 GET 10.0.0.15:443 Alexei_Romanov DIRECT/www.xxxxxxx3.com image/jpeg BLOCK_WBRS_282-AccessPol-CyberRange_DC_NoAuth-NONE-NONE-random_policy-RoutingPolicy <-,-,-,"-",-,-,-,-,"-",-,-,-,"-",-,-,"-","-",-,-,-,-,"-","-","-","-","-","-",0.00,0,-,"-","-",-,"-",-,-,"-","-"> - - - -',
'{{ mark }}{{ bsd }} {{ host }}  1588255249.000 235 cisco_wsa TCP_CLIENT_REFRESH_MISS_SSL/201 3489 HEAD http://test_web.net/contents/content3.jpg Andy_Lloyd NONE/www.xxxxxxx15.com application/x-javascript ALLOW_WBRS_162-normal_User-CyberRange_Inside_NoAuth-RFS_Transparent_Proxy_Test-DataSecurityPolicy-DefaultGroup-DIRECT <nc,9.2,-,"-",-,-,-,-,"-",-,-,-,"-",162,162,"4D747.exe","0B90665",-,-,nc,3,"Spyware","-","ccccc","bbbbb","dbca","ensrch",200.3966,1,[-],"-","-",22,"-",162,1,"-","-"> - 526 - - -',
'{{ mark }}{{ bsd }} {{ host }}  1588255249.000 564 cisco_wsa TCP_MISS_SSL/204 196 POST http://test_web.net/users/user4.jpg Alexei_Romanov NONE/www.xxxxxxx2.com image/gif DEFAULT_CASE_298-DEFAULT_ACTION_7-WebxOnly-OMSPolicy-NONE-random_policy-RoutingPolicy <IW_infr,7.0,-,"-",-,-,-,-,"-",-,-,-,"-",298,298,"FE86C.dll","2701890",0,0,IW_infr,14,"Spyware","-","Unknown","acbd","aaaaa","ensrch",209.1909,0,[Local],"-","-"> - 300 "23/042020:10:16:32 +1126" NONE -'
]

testdata_l4tm = [
'{{ mark }}{{ bsd }} {{ host }} Mon May 04 12:59:59 2020 Info: Firewall noted TCP data from 10.0.0.15 to 61.79.37.205(www.xxxxxxx7.com):1283.',
'{{ mark }}{{ bsd }} {{ host }} 04 May 2020 12:59:57 (GMT-1:00) Info: Address 143.164.34.50 discovered for www.xxxxxxx4.com (www.xxxxxxx4.com) added to firewall greylist.',
'{{ mark }}{{ bsd }} {{ host }} Mon May 04 12:59:54 2020 Info: Begin Logfile',
'{{ mark }}{{ bsd }} {{ host }} Mon May 04 12:59:49 2020 Info: Version: 9.0.0-485 SN: 848F69E6010F-JYFZWQ1',
'{{ mark }}{{ bsd }} {{ host }} 04 May 2020 12:59:59 (GMT+5:00) Info: Firewall blocked TCP data from 10.0.0.3:1148 to 96.246.56.182.',
'{{ mark }}{{ bsd }} {{ host }} Mon May 04 12:59:58 2020 Info: Time offset from UTC: 113 seconds',
'{{ mark }}{{ bsd }} {{ host }} Mon May 04 12:59:59 2020 Info: Firewall noted TCP data from 10.0.0.15 to 61.79.37.205(www.xxxxxxx7.com):1283.'
]

@pytest.mark.parametrize("event", testdata_squid)
def test_cisco_wsa_squid(record_property, setup_wordlist, get_host_key, setup_splunk, setup_sc4s, event):
    host = "cisco_wsa"

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions
    epoch = epoch[:-7]

    mt = env.from_string(event + "\n")
    message = mt.render(mark="<13>", bsd=bsd ,host=host )

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        "search index=netops _time={{ epoch }} sourcetype=\"cisco:wsa:squid\" _raw=\"{{ message }}\"")
    message1 = mt.render(mark="", bsd="", host="")
    search = st.render(epoch=epoch ,host=host, message=message1.lstrip().replace('"','\\"'))
    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

@pytest.mark.parametrize("event", testdata_l4tm)
def test_cisco_wsa_l4tm(record_property, setup_wordlist, get_host_key, setup_splunk, setup_sc4s, event):
    host = "cisco_wsa" 

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions
    epoch = epoch[:-7]

    mt = env.from_string(event + "\n")
    message = mt.render(mark="<13>", bsd=bsd, host=host)
    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        "search index=netops _time={{ epoch }} sourcetype=\"cisco:wsa:l4tm\" _raw=\"{{ message }}\"")
    
    message1 = mt.render(mark="", bsd="", host="")
    search = st.render(epoch=epoch, host=host, message=message1.lstrip())

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount) 
    record_property("message", message)

    assert resultCount == 1
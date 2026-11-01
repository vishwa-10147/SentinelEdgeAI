"""Dataset loaders (UNSW-NB15, CIC-IoT2023) and the pcap evaluator with its Suricata comparison."""
import json

import pytest
from scapy.utils import PcapWriter

from evaluation import harness, lab_pcap
from evaluation import pcap as pcap_eval

# two rows in the published UNSW-NB15_1.csv layout (no header, 49 columns)
UNSW_SCAN = ('175.45.176.1,0x000b,149.171.126.16,0x0016,tcp,REQ,0.000003,104,0,62,0,0,0,-,0,0,1,0,0,0,0,0,104,0,0,0,'
             '0,0,1421927400,1421927400,0,0,0,0,0,0,1,0,0,0,1,1,1,1,1,1,1,Reconnaissance,1')
UNSW_NORMAL = ('59.166.0.0,1390,149.171.126.6,53,udp,CON,0.001055,132,164,31,29,0,0,dns,500473.9,621800.9,2,2,0,0,0,'
               '0,66,82,0,0,0,0,1421927414,1421927414,0.017,0.013,0,0,0,0,0,0,0,0,3,7,1,3,1,1,1,,0')
UNSW_DOS = ('175.45.176.2,1043,149.171.126.10,80,tcp,FIN,0.5,1000,200,62,252,0,0,http,0,0,10,4,255,255,0,0,100,50,'
            '1,0,0,0,1421927420,1421927421,0,0,0,0,0,0,1,1,0,0,1,1,1,1,1,1,1,DoS,1')


def test_unsw_per_flow_files_without_header(tmp_path):
    p = tmp_path / 'UNSW-NB15_1.csv'
    p.write_text('\n'.join([UNSW_NORMAL, UNSW_SCAN, UNSW_DOS]) + '\n')
    events, truth = harness.load_unswnb15(str(p))
    assert [e['label'] for e in events] == ['port_scan', 'benign', 'dos']     # in time order (stime)
    scan = events[0]['record']
    assert scan['src'] == '175.45.176.1' and scan['sport'] == 11 and scan['dport'] == 22     # hex ports
    assert scan['start'] == 1421927400.0 and scan['proto'] == 'TCP'
    assert truth == [{'id': 'port_scan-0', 'kind': 'port_scan', 'src': '175.45.176.1', 'start': 1421927400.0}]
    assert events[2]['attack'] is None                    # DoS: not covered, and not counted as benign


def test_unsw_with_header_and_training_set_refused(tmp_path):
    p = tmp_path / 'with_header.csv'
    p.write_text(','.join(harness.UNSW_COLUMNS) + '\n' + UNSW_SCAN + '\n')
    assert harness.load_unswnb15(str(p))[1][0]['kind'] == 'port_scan'
    t = tmp_path / 'UNSW_NB15_training-set.csv'
    t.write_text('id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,attack_cat,label\n1,0.1,tcp,-,FIN,2,2,10,10,Normal,0\n')
    with pytest.raises(ValueError, match='no source/destination addresses'):
        harness.load_unswnb15(str(t))


def test_cic_iot2023_feature_csv_refused_with_guidance(tmp_path):
    p = tmp_path / 'part-00000.csv'
    p.write_text('flow_duration,Header_Length,Protocol Type,Duration,Rate,label\n0.1,54,6,64,3.2,DDoS-ICMP_Flood\n')
    with pytest.raises(ValueError, match='evaluation.pcap'):
        harness.load_cic_iot2023(str(p))


def small_capture(tmp_path):
    cap = lab_pcap.Capture(3)
    t = lab_pcap.T0
    s = t
    for i in range(30):                                    # benign browsing: irregular, several sites
        s += cap.rnd.uniform(5, 60)
        cap.https(s, '10.0.0.10', f'93.184.216.{10 + i % 7}', cap.rnd.randint(300, 3000), cap.rnd.randint(4000, 90000))
    for port in range(1, 120):                             # a SYN scan
        cap.tcp(t + 100 + port * 0.05, '10.0.0.66', '10.0.0.5', port, rst=True)
    cap.packets.sort()
    path = tmp_path / 'small.pcap'
    with PcapWriter(str(path)) as w:
        for _, _, p in cap.packets:
            w.write(p)
    return str(path), [{'id': 'scan-1', 'kind': 'port_scan', 'src': '10.0.0.66', 'start': t + 100}]


def test_pcap_replay_uses_packet_time_and_finds_the_scan(tmp_path):
    path, truth = small_capture(tmp_path)
    findings, info = pcap_eval.replay(path)
    assert info['packets'] > 300 and lab_pcap.T0 < info['end'] < lab_pcap.T0 + 3600     # packet time, not wall time
    result = pcap_eval.score(truth, findings)
    assert result['engine']['port_scan'] == {'instances': 1, 'detected': 1, 'median_delay_s': result['engine']['port_scan']['median_delay_s']}
    assert result['engine']['port_scan']['median_delay_s'] < 30
    assert result['engine_false_positive_sources'] == []


def test_suricata_scoring_ignores_protocol_anomalies(tmp_path):
    path, truth = small_capture(tmp_path)
    eve = tmp_path / 'eve.json'
    lines = [
        {'event_type': 'alert', 'timestamp': '2023-11-14T22:15:10.000000+0000', 'src_ip': '10.0.0.66',
         'dest_ip': '10.0.0.5', 'alert': {'signature': 'ET SCAN Example'}},
        {'event_type': 'alert', 'timestamp': '2023-11-14T22:15:10.000000+0000', 'src_ip': '10.0.0.10',
         'dest_ip': '93.184.216.34', 'alert': {'signature': 'SURICATA TLS invalid record type'}},
        {'event_type': 'flow', 'timestamp': '2023-11-14T22:15:10.000000+0000'},
    ]
    eve.write_text('\n'.join(json.dumps(x) for x in lines) + '\n')
    alerts = pcap_eval.suricata_alerts(str(eve))
    assert [a[3] for a in alerts] == ['ET SCAN Example']
    assert len(pcap_eval.suricata_alerts(str(eve), anomalies=True)) == 2
    result = pcap_eval.score(truth, pcap_eval.replay(path)[0], alerts)
    assert result['suricata']['port_scan']['detected'] == 1 and result['suricata_false_positive_sources'] == []

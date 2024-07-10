import traceback
from pyspark import SparkContext, SparkConf
import json
import re
from pyspark.accumulators import Accumulator, AccumulatorParam
from collections import defaultdict
import os
from datetime import datetime

zones = ['com', 'net', 'org', 'se']


class DictParam(AccumulatorParam):
    def zero(self, value):
        return value

    def addInPlace(self, value1, value2):
        for key in value2.keys():
            value1[key] += value2[key]
        return value1


def parse_entry(name, entry):
    if entry.startswith('include') and ':' in entry:
        return 'include', entry.split(':')[1]
    elif entry.startswith('redirect') and '=' in entry:
        return 'redirect', entry.split('=')[1].strip(' "')
    elif entry.startswith('a:') or entry == 'a':
        if ':' in entry:
            return 'a', entry.split(':')[1]
        else:
            return 'a', name
    elif entry.startswith('mx'):
        if ':' in entry:
            return 'mx', entry.split(':')[1]
        else:
            return 'mx', name
    elif entry.startswith('exists'):
        if ':' in entry:
            return 'exists', entry.split(':')[1]
        else:
            return 'exists', name
    elif entry.startswith('ptr'):
        if ':' in entry:
            return 'ptr', entry.split(':')[1]
        else:
            return 'ptr', name
    elif entry.startswith('ip4') and ':' in entry:
        return 'ip4', entry.split(':')[1]
    elif entry.startswith('ip6') and ':' in entry:
        return 'ip6', entry.split(':')[1]
    elif entry.startswith('exp') and '=' in entry:
        return 'exp', entry.split('=')[1].strip('"')
    elif entry.startswith('all'):
        return 'all', 'all'


def parse_txt(name, answer):
    includes, redirects, a, mxs, exists, ptrs, ip4s, ip6s, alls, exps = [], [], [], [], [], [], [], [], [], []
    for entry in answer.split(' '):
        if entry.startswith('v') and '=' in entry:
            continue
        elif '+' in entry or '-' in entry or '?' in entry or '~' in entry:
            ent = entry[1:]
        else:
            ent = entry
        val = parse_entry(name, ent.strip())
        if val:
            mech, item = val[0], val[1]
            if mech == 'include':
                includes.append(item)
            elif mech == 'redirect':
                redirects.append(item)
            elif mech == 'a':
                a.append(item)
            elif mech == 'mx':
                mxs.append(item)
            elif mech == 'exists':
                exists.append(item)
            elif mech == 'ptr':
                ptrs.append(item)
            elif mech == 'ip4':
                ip4s.append(item)
            elif mech == 'ip6':
                ip6s.append(item)
            elif mech == 'all':
                alls.append(item)
            elif mech == 'exp':
                exps.append(item)

    return includes, redirects, a, mxs, exists, ptrs, ip4s, ip6s, alls, exps


def process_after_join(v):
    try:
        global deployment, total, external_include, mech_a, mech_mx, mech_inc, mech_red, mech_exists, mech_ptr, mech_ip4, mech_ip6, mech_all, mech_exp
        name = v[0]
        tld = name.split('.')[-1]
        total += {tld: 1}
        if 'data' in v[1][1]:
            for answer in v[1][1]['data'].get('answers', []):
                if answer['type'] == 'TXT':
                    if 'answer' in answer and answer['answer'].lower().startswith("v=spf1"):
                        deployment += {tld: 1}
                        includes, redirects, a, mxs, exists, ptrs, ip4s, ip6s, alls, exps = parse_txt(name,
                                                                                                      answer['answer'])
                        if a:
                            mech_a += {tld: 1}
                        if mxs:
                            mech_mx += {tld: 1}
                        if includes:
                            mech_inc += {tld: 1}
                        if redirects:
                            mech_red += {tld: 1}
                        if exists:
                            mech_exists += {tld: 1}
                        if ptrs:
                            mech_ptr += {tld: 1}
                        if ip4s:
                            mech_ip4 += {tld: 1}
                        if ip6s:
                            mech_ip6 += {tld: 1}
                        if alls:
                            mech_all += {tld: 1}
                        if exps:
                            mech_exp += {tld: 1}
                        for dom in includes:
                            if not dom.endswith(name):
                                external_include += {tld: 1}
                                break
    except Exception as e:
        traceback.print_exc()
        pass


def find_out_closest_date(dt):
    min_diff = 1e8
    for mx_dt in os.listdir(base_path_mx):
        try:
            if os.path.exists(base_path_mx + mx_dt + '/dns.zip') and \
            'test' not in mx_dt and \
            'test' not in dt:
                # convert string to date object
                d1 = datetime.strptime(mx_dt, "%Y-%m-%d")
                d2 = datetime.strptime(dt, "%Y-%m-%d")
                diff = abs((d2 - d1).days)
                if diff < min_diff:
                    min_dt = mx_dt
                    min_diff = diff
        except Exception as e:
            traceback.print_exc()
            continue
    return min_dt


def extract_mx(v):
    try:
        v = json.loads(v)
        name = v[0][:-1] if v[0][-1] == '.' else v[0]
        sld = ".".join(name.split('.')[-2:])
        ld, li = [], defaultdict(list)
        for record in v[1]:
            if 'data' in record:
                for exchange in record['data'].get('exchanges', []):
                    if exchange['type'] == 'MX':
                        ld.append(exchange['name'])
                        for ip in exchange.get('ipv4_addresses', []):
                            li[exchange['name']].append(ip)
        if ld:
            return name, 'mx_present'
        return
    except Exception as e:
        traceback.print_exc()
        return


def extract_spf(line):
    try:
        v = json.loads(line)
        name = v['name'][:-1] if v['name'][-1] == '.' else v['name']
        return name, v
    except Exception as e:
        traceback.print_exc()
        return


def get_snapshot_data():
    f = open('temp/spf-data-per-mech.txt')
    lines = f.readlines()
    first_snapshot = lines[0].split()
    second_last_snapshot = lines[1].split()
    last_snapshot = lines[2].split()
    for i in range(5, len(second_last_snapshot)):  # correcting for .se zone data in the last snapshot
        last_snapshot[i] = second_last_snapshot[i]
    f.close()
    return first_snapshot, last_snapshot


def get_longitudinal_deployment():
    global deployment, total, external_include, mech_a, mech_mx, mech_inc, mech_red, mech_exists, mech_ptr, mech_ip4, mech_ip6, mech_all, mech_exp
    for dt in ["2021-10-13", '2023-03-19', '2023-03-27']:
        # if dt == "2021-10-13" or dt == '2023-03-27':  # only first and last snapshot
        #     continue
        try:
            total = sc.accumulator(defaultdict(int), DictParam())
            deployment = sc.accumulator(defaultdict(int), DictParam())
            mech_a, mech_mx, mech_inc, mech_red, mech_exists, mech_ptr, mech_ip4, mech_ip6, mech_all, mech_exp = sc.accumulator(
                defaultdict(int), DictParam()), \
                sc.accumulator(defaultdict(int), DictParam()), sc.accumulator(defaultdict(int),
                                                                              DictParam()), sc.accumulator(
                defaultdict(int), DictParam()), sc.accumulator(defaultdict(int), DictParam()), \
                sc.accumulator(defaultdict(int), DictParam()), sc.accumulator(defaultdict(int),
                                                                              DictParam()), sc.accumulator(
                defaultdict(int), DictParam()), sc.accumulator(defaultdict(int), DictParam()), \
                sc.accumulator(defaultdict(int), DictParam())
            external_include = sc.accumulator(defaultdict(int), DictParam())

            rdd_spf = sc.textFile(email_auth_hdfs_path + dt + '/SPF').map(extract_spf).filter(lambda v: v is not None)

            mx_dt = find_out_closest_date(dt)
            # print(mx_dt)

            rdd_mx = sc.textFile(mx_hdfs_path + mx_dt + '/' + 'dns/').map(extract_mx).filter(lambda v: v is not None)

            rdd = rdd_mx.join(rdd_spf)

            rdd.foreach(process_after_join)  # only process w/o join

            with open('temp/spf-data-per-mech.txt', 'a') as fout:
                fout.write(dt + ' ' + str(rdd.count()) + ' ')
                for zone in zones:
                    fout.write(str(total.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(deployment.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_a.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_mx.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_inc.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_ip4.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_ip6.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_ptr.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_all.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_exp.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_red.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(mech_exists.value[zone]) + ' ')
                for zone in zones:
                    fout.write(str(external_include.value[zone]) + ' ')
                fout.write('\n')
        except Exception as e:
            print(e)
            continue


def calc_pct_change(tld):
    f = open('temp/spf-data-per-mech.txt')
    lines = f.readlines()
    first_snapshot = lines[0].split()
    last_snapshot = lines[2].split()
    if tld == 'com':
        var, tot = 10, 6
    elif tld == 'net':
        var, tot = 11, 7
    elif tld == 'org':
        var, tot = 12, 8
    elif tld == 'se':
        var, tot = 13, 9
    print(tld, last_snapshot[var], last_snapshot[tot], first_snapshot[var], first_snapshot[tot])
    result = {
        'a': int(last_snapshot[var]) / int(last_snapshot[tot]) - int(first_snapshot[var]) / int(first_snapshot[tot]),
        'mx': int(last_snapshot[var + 4]) / int(last_snapshot[tot]) - int(first_snapshot[var + 4]) / int(
            first_snapshot[tot]),
        'include': int(last_snapshot[var + 8]) / int(last_snapshot[tot]) - int(first_snapshot[var + 8]) / int(
            first_snapshot[tot]),
        'ip4': int(last_snapshot[var + 12]) / int(last_snapshot[tot]) - int(first_snapshot[var + 12]) / int(
            first_snapshot[tot]),
        'ip6': int(last_snapshot[var + 16]) / int(last_snapshot[tot]) - int(first_snapshot[var + 16]) / int(
            first_snapshot[tot]),
        'ptr': int(last_snapshot[var + 20]) / int(last_snapshot[tot]) - int(first_snapshot[var + 20]) / int(
            first_snapshot[tot]),
        'all': int(last_snapshot[var + 24]) / int(last_snapshot[tot]) - int(first_snapshot[var + 24]) / int(
            first_snapshot[tot]),
        'exists': int(last_snapshot[var + 36]) / int(last_snapshot[tot]) - int(first_snapshot[var + 36]) / int(
            first_snapshot[tot]),
    }
    rounded_result = {}
    for key in result:
        rounded_result[key] = round(result[key] * 100, 1)
    print(tld, rounded_result)


# PYSPARK_DRIVER_PYTHON=`which python` PYSPARK_PYTHON=`which python` spark-submit <>
if __name__ == "__main__":
    conf = SparkConf() \
        .setAppName("generate-table-1") \
        # .setMaster("local[*]")

    sc = SparkContext(conf=conf)
    sc.setLogLevel("ERROR")

    base_path = '/net/data/email-sender-auth/'
    base_path_mx = '/net/data/mta-sts/'
    mx_hdfs_path = 'hdfs:///user/ashiq/mta-sts-management/dns-records-by-date/'
    email_auth_hdfs_path = 'hdfs:///user/ashiq/email-sender-auth-management/dns-records-by-date/'

    total = sc.accumulator(defaultdict(int), DictParam())
    deployment = sc.accumulator(defaultdict(int), DictParam())
    external_include = sc.accumulator(defaultdict(int), DictParam())
    mech_a, mech_mx, mech_inc, mech_red, mech_exists, mech_ptr, mech_ip4, mech_ip6, mech_all, mech_exp = sc.accumulator(
        defaultdict(int), DictParam()), \
        sc.accumulator(defaultdict(int), DictParam()), sc.accumulator(defaultdict(int), DictParam()), sc.accumulator(
        defaultdict(int), DictParam()), sc.accumulator(defaultdict(int), DictParam()), \
        sc.accumulator(defaultdict(int), DictParam()), sc.accumulator(defaultdict(int), DictParam()), sc.accumulator(
        defaultdict(int), DictParam()), sc.accumulator(defaultdict(int), DictParam()), \
        sc.accumulator(defaultdict(int), DictParam())
    get_longitudinal_deployment()
    first_snapshot, last_snapshot = get_snapshot_data()
    print("Data for Table 1")
    print("# of domains with MX for com, net, org, se respectively:", last_snapshot[2], last_snapshot[3], last_snapshot[4], last_snapshot[5])
    print("# of domains with SPF enabled for com, net, org, se respectively:", last_snapshot[6], last_snapshot[7], last_snapshot[8], last_snapshot[9])
    print("# of domains with SPF having includes for com, net, org, se respectively:", last_snapshot[18], last_snapshot[19], last_snapshot[20], last_snapshot[21])
    print("# of domains with SPF having external includes for com, net, org, se respectively:", last_snapshot[-4], last_snapshot[-3], last_snapshot[-2], last_snapshot[-1])
    print("Data for Table 2")
    calc_pct_change('com')
    calc_pct_change('net')
    calc_pct_change('org')
    calc_pct_change('se')

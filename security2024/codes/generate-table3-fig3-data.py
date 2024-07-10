from collections import defaultdict
from pyspark import SparkContext, SparkConf
import json
from pyspark.accumulators import Accumulator, AccumulatorParam
import traceback
import re


class ListAccumulator(AccumulatorParam):
    def zero(self, init_value: list):
        return init_value

    def addInPlace(self, v1: list, v2: list):
        return v1 + v2


class DictParam(AccumulatorParam):
    def zero(self, value):
        return value

    def addInPlace(self, value1, value2):
        for key in value2.keys():
            value1[key] += value2[key]
        return value1


def common_stats(v):
    try:
        global ns_failure, not_deployed, multiple_spf, nxdomain, lookups_10, lookups, lookups_list, lookups_with_inc, lookups_wo_inc
        v = json.loads(v)
        if 'error' in v and isinstance(v['error'], str):
            if 'No TXT record found' in v['error']:  # no txt record
                not_deployed += 1
            elif 'No SPF record found' in v['error']:  # txt record exists but none of them are spf record
                not_deployed += 1
            elif 'Unable to look up TXT record for' in v['error']:
                if 'NXDOMAIN' in v['error']:
                    nxdomain += 1
                else:  # refused/servfail
                    ns_failure += 1
            elif 'Multiple SPF policies found for' in v['error']:
                multiple_spf += 1
        if 'lookups' in v and v['lookups'] > 10:
            lookups_10 += 1
        if 'lookups' in v and 'query' in v:
            lookups_list += [v['lookups']]
        inc_present = False
        if 'lookups' in v and 'expanded' in v and 'query' in v and v['query'] in v['expanded']:
            spf = v['expanded'][v['query']].get('spf')
            if 'include:' in spf:
                lookups_with_inc += [v['lookups']]
                inc_present = True
        if not inc_present and 'lookups' in v:
            lookups_wo_inc += [v['lookups']]
        return
    except Exception as e:
        traceback.print_exc()
        return


def jsonize(v):
    try:
        jsonized = json.loads(v)
        if 'query' not in jsonized:
            return
        return v, jsonized
    except Exception as e:
        return


def create_cdf_file(array, how, fp):
    '''
        how: if total, cdf will be made using total sum of the list; for example: [0, 1, 1, 2, 3] -> [0, 2/7, 4/7, 1]
        if freq, cdf will be made using freq sum of the list: for example: [0, 0, 1, 1, 2, 3] -> [0 -> (2/6), 1 -> (4/6), 2 -> (5/6), ...]
    '''
    array = sorted(array)
    total = sum(array) if how == 'total' else len(array)
    cum = 0
    with open(fp, 'w') as f:
        for ind, i in enumerate(array):
            cum += i if how == 'total' else 1
            if ind < len(array) - 1 and i != array[ind + 1]:
                f.write(str(i) + ' ' + str(cum / total))
                f.write('\n')
            elif ind == len(array) - 1:
                f.write(str(i) + ' ' + str(cum / total))
                f.write('\n')


def errors(v):
    try:
        v = json.loads(v)
        errors = {}
        if 'expanded' in v:
            for domain in v['expanded']:
                errors[domain] = (v['expanded'][domain]['errors'])
            return v['query'], errors
        else:
            return
    except Exception as e:
        return


def find_out_errors_in_spf():
    result = rdd.map(errors).filter(lambda v: v is not None)
    f = open('temp/spf-policy-errors.txt', 'w')
    for ind, i in enumerate(result.collect()):
        f.write(i[0] + ' ' + json.dumps(i[1]) + '\n')


def count_errors_in_spf():
    fn = 'temp/spf-policy-errors.txt'
    f = open(fn)
    cnt = defaultdict(int)
    for i in f.readlines():
        a, b = i.split()[0], json.loads(" ".join(i.split()[1:]))
        s = set()
        for key in b:
            for item in b[key]:
                hey = re.findall("'([^'']*)'", item)
                for quote in hey:
                    item = item.replace(quote, '')
                if 'Invalid directive' in item:
                    item = 'Invalid directive'
                elif 'Too many DNS lookups' in item:
                    continue  # calculated already, so skipping
                elif 'Unknown directive' in item:
                    item = 'Unknown directive'
                elif 'Invalid IP' in item:
                    item = 'Invalid IP'
                s.add(item)
        for item in s:
            cnt[item] += 1
    # print(cnt)  
    # {"Recursive inclusion of ''.": 55664, 'Invalid IP': 23058, "Multiple SPF policies found for ''.": 82370, 'Unknown directive': 53165, "Invalid definition '' for domain ''.": 7790, "More than 10 MX records for domain '' found.": 511, 'Invalid directive': 2117}
    for i in cnt:
        if 'Invalid IP' in i:
            print('Invalid value', cnt[i])
        elif 'Unknown directive' in i:
            print('Unknown mechanism', cnt[i])
        elif 'Multiple SPF policies' in i:
            print('Multiple SPF records', cnt[i])
        elif 'Recursive inclusion' in i:
            print('Recursive value', cnt[i])
        elif 'Invalid directive' in i:
            print('Missing values for a and mx', cnt[i])
        elif 'Invalid definition' in i:
            print('Missing values for ip4 and ip6', cnt[i])

def warnings(v):
    try:
        v = json.loads(v)
        errors = {}
        if 'expanded' in v:
            for domain in v['expanded']:
                errors[domain] = (v['expanded'][domain]['warnings'])
            return v['query'], errors
        else:
            return
    except Exception as e:
        return


def find_out_warnings_in_spf():
    result = rdd.map(warnings).filter(lambda v: v is not None)
    f = open('temp/spf-policy-warnings', 'w')
    for ind, i in enumerate(result.collect()):
        f.write(i[0] + ' ' + json.dumps(i[1]) + '\n')


def count_warnings_in_spf():
    fn = 'temp/spf-policy-warnings'
    f = open(fn)
    cnt = defaultdict(int)
    for i in f.readlines():
        a, b = i.split()[0], json.loads(" ".join(i.split()[1:]))
        s = set()
        for key in b:
            for item in b[key]:
                hey = re.findall("'([^'']*)'", item)
                for quote in hey:
                    item = item.replace(quote, '')
                if 'SPF record' in item and 'long' in item:
                    item = 'SPF record too long'
                elif 'directive is not last in ' in item and ' policy - ignoring  subsequent directives.' in item:
                    item = 'all directive is not last in <h> policy - ignoring  subsequent directives.'
                elif 'Ignored' in item and ' policy with' in item:
                    item = "'redirect' ignored because of 'all' mechanism"
                elif 'Unable to look up TXT record for' in item:
                    item = "Unable to look up TXT record"
                s.add(item)
        for item in s:
            cnt[item] += 1
    # print(cnt)
    for i in cnt:
        if 'No MX record for domain' in i:
            print('Missing MX', cnt[i])
        elif 'Unable to look up TXT record' in i:
            print('Missing TXT', cnt[i])


def find_out_missing_a_domain_in_spf():
    def missing_a(v):
        try:
            v = json.loads(v)
            errors = {}
            if 'expanded' in v:
                for domain in v['expanded']:
                    for evaluation in ['pass', 'fail', 'softfail', 'neutral']:
                        if evaluation in v['expanded'][domain]:
                            if 'a' in v['expanded'][domain][evaluation]:
                                if len(v['expanded'][domain][evaluation]['a']['ips']) == 0:
                                    return 1
            return 0
        except Exception as e:
            return 0

    result = rdd.map(missing_a).sum()
    print('Missing A', result)


# PYSPARK_DRIVER_PYTHON=`which python` PYSPARK_PYTHON=`which python` spark-submit <>
if __name__ == "__main__":
    conf = SparkConf() \
        .setAppName("generate-table3-fig3-data") \
        # .setMaster("local[*]")

    sc = SparkContext(conf=conf)
    sc.setLogLevel("ERROR")
    input_path = "hdfs:///user/ashiq/spf-exploit/jschauma/"

    domains_with_mx_records = "hdfs:///user/ashiq/spf-exploit/domains-with-mx-records.txt"

    not_deployed, multiple_spf, ns_failure, nxdomain, lookups_10 = sc.accumulator(0), sc.accumulator(0), sc.accumulator(
        0), sc.accumulator(0), sc.accumulator(0)
    lookups = sc.accumulator(defaultdict(int), DictParam())
    lookups_list = sc.accumulator([], ListAccumulator())
    lookups_with_inc = sc.accumulator([], ListAccumulator())
    lookups_wo_inc = sc.accumulator([], ListAccumulator())

    # filtering out domain w/o mx records
    rdd = sc.textFile(input_path).map(jsonize).filter(lambda v: v is not None).map(
        lambda v: (v[1]['query'], v[0])).distinct()
    # rdd = rdd.persist()
    rdd2 = sc.textFile(domains_with_mx_records).map(lambda v: v.strip()[:-1]).map(lambda v: (v, 'empty')).cache()
    rdd = rdd.join(rdd2).map(lambda v: v[1][0])  # .distinct()
    # rdd.map(json.dumps).saveAsTextFile("hdfs:////user/ashiq/spf-exploit/jschauma-filtered-with-mx/")

    rdd.foreach(common_stats)

    json.dump(lookups_wo_inc.value, open('temp/latest-snapshot-lookups-wo-inc.json', 'w'))
    json.dump(lookups_with_inc.value, open('temp/latest-snapshot-lookups-with-inc.json', 'w'))

    create_cdf_file(json.load(open('temp/latest-snapshot-lookups-wo-inc.json')), how='freq',
                    fp='temp/latest-snapshot-include-absent')
    create_cdf_file(json.load(open('temp/latest-snapshot-lookups-with-inc.json')), how='freq',
                    fp='temp/latest-snapshot-include-present')

    find_out_errors_in_spf()
    count_errors_in_spf()
    find_out_warnings_in_spf()
    count_warnings_in_spf()
    find_out_missing_a_domain_in_spf()

    """
    Recursive value 55664
    Invalid value 23058
    Multiple SPF records 82370
    Unknown mechanism 53165
    Missing values for ip4 and ip6 7790
    Missing values for a and mx 2117
    Missing MX 324524
    Missing TXT 85140
    Missing TXT 1
    Missing A 280890
    """

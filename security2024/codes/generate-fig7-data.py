import os
import sys
from collections import defaultdict
import json
import datetime


def process_query(query):
    """ Takes a Bind query log entry and splits it to see how many
        entries it contains. The query log format can change between
        releases and can grow or shrink if views are used.
        Known query log formats:
        Bind 9.3 query log format:
        20-Sep-2016 11:26:15.510 query: info: client 1.2.3.4#60010: \
        view standard: query: blip.prefetch.net IN AAAA +
        Bind 9.9 query log format:
        20-Sep-2016 11:24:30.025 query: info: client 1.2.3.4#61687 \
        (blip.prefetch.net): view standard: query: blip.prefetch.net
        IN A + (10.1.1.1)
        # Bind 9.3 w/o views
        08-Nov-2016 14:05:59.996 query: info: client 1.2.3.4#7619: \
        query: 10.10.10.10.in-addr.arpa IN PTR -E
        # Bind 9.10
        18-Jan-2018 13:13:07.889 client 1.2.3.4#42872 (prefetch.net): \
        query: prefetch.net IN ANY + (1.2.3.4)
    """
    words_to_strip = ["query:", "info:", "client", "view", "standard:", "queries:"]
    chopped = ' '.join(i for i in query.split() if i not in words_to_strip).split()
    # print(chopped, len(chopped))

    if len(chopped) == 10 or len(chopped) == 12:
        date = chopped[0]
        time = chopped[1]
        timestamp = date + " " + time
        format = '%d-%b-%Y'
        datetime_obj = datetime.datetime.strptime(date, format)
        # print(datetime_obj)
        # if datetime_obj >= datetime.datetime.strptime("2024-04-11 00:00:00", "%Y-%m-%d %H:%M:%S"):
        #     return
        client_ip = chopped[3].split("#")[0]
        rr_type = chopped[7]
        qname = chopped[5]
        flags = chopped[8]
    else:
        print("Unknown query log format")
        print("Offending line -> %s" % query)
        sys.exit(1)

    return timestamp, qname, rr_type, client_ip, flags


def _create_hash(val):
    import hashlib
    id_ = hashlib.md5(bytes(val, 'utf-8')).hexdigest()
    return id_[0:8]


def create_mapping(identifier, d):
    for i in range(0, 51):
        for j in ['test1', 'test2']:
            total_id = str(i) + '.' + j + '.' + identifier
            hash = _create_hash(total_id)
            d[hash] = total_id


def read_hashes():
    hashes = json.load(open(base_path + 'hashed-scanned-mtas.json'))
    # print(len(hashes), hashes[0:5])
    return hashes


def read_logs(domain='dmarcanalysis.net'):
    a, b, c = 0, 0, 0
    dirs = ['s1', 's2'] + ['s1-expt2', 's2-expt2']
    void_set = set([i for i in range(15, 51)])
    for sd in dirs:
        for f in os.listdir(log_path + sd + '/'):
            path = os.path.join(log_path + sd + '/', f)
            lines = open(path).readlines()
            for line in lines:
                a += 1
                result = process_query(line)
                if not result:
                    continue
                if result:
                    timestamp, qname, rr_type, client_ip, flags = result
                # print(timestamp, qname, rr_type, client_ip)
                if rr_type == 'TXT' and domain in qname.lower():
                    b += 1
                    hash_ = qname.split('.')[0]
                    if hash_ in bind2mx1 or hash_ in bind2mx2:
                        c += 1
                        no, expt, id_ = bind2mx1[hash_].split('.') if hash_ in bind2mx1 else bind2mx2[hash_].split('.')
                        if expt == 'test1':
                            total_cnt_expt1[id_] += 1
                            if no not in query_set_expt1[id_]:
                                total_unique_cnt_expt1[id_] += 1
                                query_set_expt1[id_].add(no)
                        else:
                            total_cnt_expt2[id_] += 1
                            if int(no) in void_set:
                                void_cnt[id_] += 1
                            if no not in query_set_expt2[id_]:
                                total_unique_cnt_expt2[id_] += 1
                                if int(no) in void_set:
                                    void_unique_cnt[id_] += 1
                                query_set_expt2[id_].add(no)

    print('no. of lines in log', a, 'no. of TXT query rows', b, 'no. of TXT query rows in mapping', c)


def create_cdf_file(array, how, fp):
    '''
        how: if total, cdf will be made using total sum of the list; for example: [0, 1, 1, 2, 3] -> [0, 2/7, 4/7, 1]
        if freq, cdf will be made using freq sum of the list: for example: [0, 0, 1, 1, 2, 3] -> [0 -> (2/6), 1 -> (4/6), 2 -> (5/6), ...]
    '''
    array = sorted(array)
    total = sum(array) if how == 'total' else len(array)
    print(total)
    cum = 0
    with open(fp, 'w') as f:
        for ind, i in enumerate(array):
            cum += i if how == 'total' else 1
            # print(i, cum)
            if ind < len(array) - 1  and i != array[ind+1]:
                f.write(str(i) + ' ' + str(cum/total))
                f.write('\n')
            elif ind == len(array) - 1:
                f.write(str(i) + ' ' + str(cum/total))
                f.write('\n')


if __name__ == "__main__":
    base_path = ''
    log_path = base_path + 'bind-logs/'
    hashes = read_hashes()
    print('# of servers scanned', len(set(hashes)))
    bind2mx1, bind2mx2 = {}, {}
    void_nos = set([i for i in range(15, 51)])
    is_missing_log_indicator = set([0, 1, 2, 16, 35, 3, 36, 50, 15])
    are_log_line_indicators_present = defaultdict(lambda: False)
    total_cnt_expt1, total_unique_cnt_expt1, query_set_expt1 = defaultdict(int), defaultdict(int), defaultdict(set)
    total_cnt_expt2, total_unique_cnt_expt2, query_set_expt2, void_unique_cnt, void_cnt = defaultdict(int), defaultdict(
        int), defaultdict(set), defaultdict(int), defaultdict(int)
    for ind, i in enumerate(hashes[:1000000]):
        if ind % 100000 == 0:
            print('Creating mapping. ' + str(len(bind2mx1)/1886825) + '% done. Please wait...')
        create_mapping(i, bind2mx1)
    for ind, i in enumerate(hashes[1000000:]):
        if ind % 100000 == 0:
            print('Creating mapping. ' + str(50 + len(bind2mx2)/1886825) + '% done. Please wait...')
        create_mapping(i, bind2mx2)
    # print('# of keys in mapping', len(bind2mx1) + len(bind2mx2))
    read_logs()
    with open('temp/dns-lookup-count-scanning.txt', 'w') as fout:
        temp = {}
        for key in total_unique_cnt_expt1:
            temp[key] = max(total_cnt_expt1[key], total_cnt_expt2[key])
        for key in total_unique_cnt_expt2:
            temp[key] = max(total_cnt_expt1[key], total_cnt_expt2[key])
        for key in temp:
            fout.write(key + ' ' + str(temp[key]) + ' ' + str(void_cnt[key]) + '\n')
    print('No. of servers that queried: ', len(total_unique_cnt_expt1))
    for key in query_set_expt1:
        are_log_line_indicators_present[key] = True if is_missing_log_indicator.issubset(
            query_set_expt1[key]) else False
    for key in query_set_expt2:
        are_log_line_indicators_present[key] = True if is_missing_log_indicator.issubset(
            query_set_expt2[key]) else False

    # expt-1
    # Finding potential servers with no total lookup limit
    x1 = set([(key, total_unique_cnt_expt1[key]) for key in total_unique_cnt_expt1 if
              total_unique_cnt_expt1[key] >= 51 or (
                          are_log_line_indicators_present[key] and total_unique_cnt_expt1[key] >= 45)])
    x1_prime = set([(key, total_unique_cnt_expt2[key]) for key in total_unique_cnt_expt2 if
                    total_unique_cnt_expt2[key] >= 51 or (
                    (are_log_line_indicators_present[key] and total_unique_cnt_expt2[key] >= 45))])
    x1 = x1.union(x1_prime)
    # print(len(x1), len(x1_prime), len(x1.intersection(x1_prime)))
    # Finding potential servers with more than 51 queries
    y1 = set([(key, total_cnt_expt1[key]) for key in total_cnt_expt1 if total_cnt_expt1[key] >= 51 or (
                are_log_line_indicators_present[key] and total_unique_cnt_expt1[key] >= 45)])
    y1_prime = set([(key, total_cnt_expt2[key]) for key in total_cnt_expt2 if total_cnt_expt2[key] >= 51 or (
                are_log_line_indicators_present[key] and total_unique_cnt_expt2[key] >= 45)])
    y1 = y1.union(y1_prime)
    # expt-2
    # Finding potential servers with no void lookup limit
    x2 = set([(key, void_unique_cnt[key]) for key in void_unique_cnt if void_unique_cnt[
        key] >= 31])  # 31 seems to be a safe choice since void lookup limit should not be greater than 30
    # expt-1
    print('# of potentially vulnerable servers with no total lookup limit', len(x1))
    print('Servers that made more than 51 queries', len(y1))
    # expt-2
    print('# of potentially vulnerable servers with no void lookup limit', len(x2))
    common_potentially_vulnerable_servers = set([i[0] for i in x1]).intersection(set([i[0] for i in x2]))
    print('# of potentially vulnerable servers common in both experiments', len(common_potentially_vulnerable_servers))

    with open('temp/dns_lookup_count_scanning_rebuttal.txt') as fin:
        lines = fin.readlines()
        test1 = []
        test2 = []
        for line in lines:
            x, y, z = line.split()
            test1.append(int(y))
            test2.append(int(z))
    create_cdf_file(test1, 'freq', 'temp/vuln-scan-test1.txt')
    create_cdf_file(test2, 'freq', 'temp/vuln-scan-test2.txt')

    print('end, press ctrl-c to quit')

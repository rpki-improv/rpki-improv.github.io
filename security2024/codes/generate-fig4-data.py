from collections import defaultdict


def create_cdf_centralization(limit):
    if limit:
        f = open('temp/spf-include-centralization-over-10.txt')
    else:
        f = open('temp/spf-include-centralization.txt')
    lines = f.readlines()
    centralization = {}
    for line in lines:
        ind, domain, number = line.split()
        centralization[domain] = int(number)
    x = list(centralization.values())
    x.sort(reverse=True)
    total = sum(x)
    cum = 0
    if limit:
        foutname = 'temp/cdf-vs-include-centralization-over-10.txt'
    else:
        foutname = 'temp/cdf-vs-include-centralization.txt'
    with open(foutname, 'w') as f:
        for ind, i in enumerate(x):
            cum += i
            if ind < len(x) - 1  and i != x[ind+1]:
                f.write(str(ind) + ' ' + str(i) + ' ' + str(cum/total))
                f.write('\n')
            elif ind == len(x) - 1:
                f.write(str(ind) + ' ' + str(i) + ' ' + str(cum/total))
                f.write('\n')


# python3 <>
if __name__ == "__main__":
    create_cdf_centralization(False)
    create_cdf_centralization(True)







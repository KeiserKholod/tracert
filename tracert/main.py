import argparse

from tracert import Tracert

parser = argparse.ArgumentParser()
parser.add_argument('host', type=str, help="Enter hostname t to trace route")
parser.add_argument("--ttl", type=int, help="Enter ttl", default=30)

args = parser.parse_args()
tracert = Tracert(args.host, args.ttl)
result = tracert.do_trace()
counter = 0
for i in result:
    counter += 1
    print(f'{counter}. {i}')

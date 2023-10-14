import os
import json
import platformdirs
from collections import Counter


def main():
    config_dir = platformdirs.user_config_dir('PythonCliAuth')
    filename = os.path.join(config_dir, 'tokens.json')
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            tokens = json.load(f)
        providers = Counter(s.split('/')[0] for s in tokens.keys())
        print('Which provider\'s tokens to delete:\n')
        names = sorted(providers.keys())
        for i, p in enumerate(names):
            print(f'{i+1}. {p} ({providers[p]})')
        print('0. All of them')
        print('Q. Cancel')
        while True:
            inp = input('> ').strip().lower()
            if inp:
                break
        try:
            n = int(inp)
            if n == 0:
                os.remove(filename)
            else:
                tokens = {k: v for k, v in tokens.items()
                          if not k.startswith(names[n - 1] + '/')}
                with open(filename, 'w') as f:
                    json.dump(tokens, f)
        except ValueError:
            print('Okay, doing nothing.')

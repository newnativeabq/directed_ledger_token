"""
Client - Off Chain

Contains all necessary methods to be implemented in off chain code.  
The smart contract may or may not be able to assume some of this functionality.
"""

import json
from copy import copy
from .utils import *

class Client():
    def __init__(self, wallet=None):
        self.wallet = wallet

    def generate_ledger(self, n, wallet: Wallet):
        empty_block = {'value': None, 'signature': None}
        return {
            'steps': n,
            'pubkey': wallet.pub_key_str,
            'blocks': [empty_block for _ in range(n)],
        }

    def validate_ledger(self, ledger, wallet: Wallet, message='valid') -> dict:
        def _find_null_value(ledger) -> int:
            for i, d in enumerate(ledger['blocks']):
                if (d['value'] == 'NULL') or (d['value'] is None):
                    return i

        def _sign_ledger(ledger, vpos, wallet):
            lstring = json.dumps(ledger)  ## DEBUG - protocol buffer class object may have string method
            slot = copy(ledger['blocks'][vpos])
            slot['value'] = message
            slot['signature'] = wallet.sign(lstring).decode('utf-8')
            ledger['blocks'][vpos] = slot
            return ledger

        vpos = _find_null_value(ledger)
        assert vpos is not None, 'No validation slot remaining'
        print('sigining slot', vpos)
        return _sign_ledger(ledger, vpos, wallet)


import hashlib
import clvm
from standard_wallet.wallet import Wallet, make_solution
from chiasim.validation.Conditions import ConditionOpcode
from chiasim.hashable import Program, ProgramHash, Coin
from clvm_tools import binutils
from chiasim.puzzles.p2_delegated_puzzle import puzzle_for_pk
from chiasim.hashable import CoinSolution, SpendBundle, BLSSignature
from chiasim.hashable.CoinSolution import CoinSolutionList


class CCWallet(Wallet):

    def __init__(self):
        super().__init__()
        self.my_cores = []  # core is stored as a string
        self.my_coloured_coins = dict()  # {coin: (innerpuzhash, core)}
        return

    def notify(self, additions, deletions):
        self.cc_notify(additions, deletions)
        super().notify(additions, deletions)

    def cc_notify(self, additions, deletions):
        for coin in additions:
            for i in reversed(range(self.next_address)):
                innerpuz = puzzle_for_pk(self.extended_secret_key.public_child(i).get_public_key().serialize())
                for core in self.my_cores:
                    if ProgramHash(self.cc_make_puzzle(ProgramHash(innerpuz), core)) == coin.puzzle_hash:
                        self.my_coloured_coins[coin] = (innerpuz, core)
        for coin in deletions:
            if coin in self.my_coloured_coins:
                self.my_coloured_coins.pop(coin)
        return

    def cc_can_generate(self, finalpuzhash):
        for i in reversed(range(self.next_address)):
            innerpuzhash = ProgramHash(puzzle_for_pk(self.extended_secret_key.public_child(i).get_public_key().serialize()))
            for core in self.my_cores:
                if ProgramHash(self.cc_make_puzzle(innerpuzhash, core)) == finalpuzhash:
                    return True
        return False

    def cc_add_core(self, core):
        self.my_cores.append(core)
        return

    # This is for generating a new set of coloured coins - this may be moved out of this wallet
    def cc_generate_spend_for_genesis_coins(self, amount, innerpuzhash, genesisCoin=None):
        if genesisCoin is None:
            my_utxos_copy = self.temp_utxos.copy()
            genesisCoin = my_utxos_copy.pop()
            while genesisCoin.amount < amount and len(my_utxos_copy) > 0:
                genesisCoin = my_utxos_copy.pop()
            if genesisCoin.amount < amount:
                return None  # no reason why a coin couldn't have two parents, just want to make debugging simple for now
        core = self.cc_make_core(genesisCoin.name())
        self.cc_add_core(core)
        spends = []
        change = genesisCoin.amount - amount
        newpuzzle = self.cc_make_puzzle(innerpuzhash, core)
        # print(f"Actual full puzzle: {binutils.disassemble(newpuzzle)}")
        newpuzzlehash = ProgramHash(newpuzzle)
        # Aped from wallet.generate_unsigned_transaction()
        puzzle_hash = genesisCoin.puzzle_hash
        pubkey, secretkey = self.get_keys(puzzle_hash)
        puzzle = self.puzzle_for_pk(pubkey.serialize())
        primaries = [{'puzzlehash': newpuzzlehash, 'amount': amount}]
        if change > 0:
            changepuzzlehash = self.get_new_puzzlehash()
            primaries.append(
                {'puzzlehash': changepuzzlehash, 'amount': change})
            # add change coin into temp_utxo set
            self.temp_utxos.add(Coin(genesisCoin, changepuzzlehash, change))
        solution = make_solution(primaries=primaries)
        spends.append((puzzle, CoinSolution(genesisCoin, solution)))
        self.temp_balance -= amount

        return self.sign_transaction(spends)

    # we use it to merge the outputs of two programs that create lists
    def merge_two_lists(self, list1=None, list2=None):
        if (list1 is None) or (list2 is None):
            return None
        ret = f"((c (q ((c (f (a)) (a)))) (c (q ((c (i ((c (i (f (r (a))) (q (q ())) (q (q 1))) (a))) (q (f (c (f (r (r (a)))) (q ())))) (q ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (c (c (f (f (r (a)))) (f (r (r (a))))) (q ())))))))) (a)))) (c {list1} (c {list2} (q ()))))))"
        return ret

    # This is for spending an existing coloured coin
    def cc_make_puzzle(self, innerpuzhash, core):
        puzstring = f"(r (c (q 0x{innerpuzhash}) ((c (q {core}) (a)))))"
        #print(f"DEBUG Puzstring: {puzstring}")
        return Program(binutils.assemble(puzstring))

    # Typically called only once per colour
    def cc_make_core(self, originID):
        create_outputs = f"((c (f (r (r (r (a))))) (f (r (r (r (r (a))))))))"
        sum_outputs = f"((c (q ((c (f (a)) (a)))) (c (q ((c (i (f (r (a))) (q ((c (i (= (f (f (f (r (a))))) (q 0x{ConditionOpcode.CREATE_COIN.hex()})) (q (+ (f (r (r (f (f (r (a))))))) ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (q ()))))))) (q (+ (q ()) ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (q ())))))))) (a)))) (q (q ()))) (a)))) (c {create_outputs} (q ())))))"

        # python_loop = f"""
        #((c (i (f (r (a)))
        #   (q ((c (i (= (f (f (f (r (a))))) (q 51))
    #         (q {new_createcoin})
    #         (q ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (c (f (r (r (a)))) (c (c (f (f (r (a)))) (f (r (r (r (a)))))) (q ()))))))))
    #            ) (a)))
    #        )
    #        (q (f (r (r (r (a))))))
    #    ) (a)))"""

        # below is confirmed working raw chialisp - to be converted to nice python above later
        replace_generated_createcoins = f"((c (q ((c (f (a)) (a)))) (c (q ((c (i (f (r (a))) (q ((c (i (= (f (f (f (r (a))))) (q 0x{ConditionOpcode.CREATE_COIN.hex()})) (q ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (c (f (r (r (a)))) (c (c (c (q 0x{ConditionOpcode.CREATE_COIN.hex()}) (c (sha256tree (c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (f (f (r (a)))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (r (r (a)))) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))) (c (f (r (r (f (f (r (a))))))) (q ())))) (f (r (r (r (a)))))) (q ())))))))) (q ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (c (f (r (r (a)))) (c (c (f (f (r (a)))) (f (r (r (r (a)))))) (q ())))))))) ) (a))) ) (q (f (r (r (r (a)))))) ) (a)))) (c {create_outputs} (c (f (a)) (c (q ()) (q ())))))))"

        add_core_to_parent_innerpuzhash = "(c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (f (r (a))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (a)) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))"
        add_core_to_my_innerpuz_reveal = "(c (q 7) (c (c (q 5) (c (c (q 1) (c (sha256tree (f (r (r (r (a)))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (a)) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))"

        # Because we add core to our innerpuz reveal as part of our ASSERT_MY_ID we also check that our innerpuzreveal is correct
        assert_my_parent_is_origin = f"(c (q 0x{ConditionOpcode.ASSERT_MY_COIN_ID.hex()}) (c (sha256 (f (r (a))) (sha256tree {add_core_to_my_innerpuz_reveal}) (uint64 (f (r (r (a)))))) (q ())))"

        assert_my_parent_follows_core_logic = f"(c (q 0x{ConditionOpcode.ASSERT_MY_COIN_ID.hex()}) (c (sha256 (sha256 (f (f (r (a)))) (sha256tree {add_core_to_parent_innerpuzhash}) (uint64 (f (r (r (f (r (a)))))))) (sha256tree {add_core_to_my_innerpuz_reveal}) (uint64 (f (r (r (a)))))) (q ())))"

        # heritage_check = f"((c (i (l (f (r (a)))) (q {assert_my_parent_follows_core_logic}) (q ((c (i (= (q 0x{originID}) (f (r (a)))) (q {assert_my_parent_is_origin}) (q (x))) (a)))) ) (a)))"

        add_core_to_aggregator_innerpuzhash = f"(c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (f (r (r (r (r (r (a))))))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (a)) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))"
        create_a_puz_for_cn = f"(c (q #r) (c (c (q #c) (c (c (q #q) (c (sha256 (sha256 (f (f (r (a)))) (sha256tree {add_core_to_parent_innerpuzhash}) (uint64 (f (r (r (f (r (a)))))))) {add_core_to_my_innerpuz_reveal} (uint64 (f (r (r (f (r (a))))))) (q ()))) (q ((q ()))))) (q ())))"
        consume_a = f"(c (q 52) (sha256 (sha256 (f (f (r (r (r (r (r (a)))))))) (sha256tree {add_core_to_aggregator_innerpuzhash}) (uint64 (f (r (r (f (r (r (r (r (r (a)))))))))))) (sha256tree {create_a_puz_for_cn}) (uint64 (q 0))))"

        create_e_puz = f"(c (q #r) (c (c (q #r) (c (c (q #c) (c (c (q #q) (c (sha256 (f (f (r (r (r (r (r (a)))))))) (sha256tree {add_core_to_aggregator_innerpuzhash}) (uint64 (f (r (r (f (r (r (r (r (r (a)))))))))))) (q ()))) (c (c (q #c) (c (c (q #uint64) (c (c (q #q) (c {sum_outputs} (q ()))) (q ()))) (q ((q ()))))) (q ())))) (q ()))) (q ())))"
        create_e = f"(c (q 51) (c {create_e_puz} (c (uint64 (q 0)) (q ()))))"



        consume_es_generate_as = f"((c (q ((c (f (a)) (a)))) (c (q ((c (i (f (r (a))) (q ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (c (f (r (r (a)))) (c (f (r (r (r (a))))) (c (c (c (q 51) (c (sha256tree (c (q 7) (c (c (q 5) (c (c (q 1) (c (sha256 (f (f (f (r (a))))) (sha256tree (c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (f (f (r (a)))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (r (r (r (a))))) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))) (uint64 (f (r (r (f (f (r (a))))))))) (q ()))) (q ((q ()))))) (q ())))) (q (0x0000000000000000)))) (c (c (q 53) (c (sha256 (sha256 (f (f (f (r (a))))) (sha256tree (c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (f (f (r (a)))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (r (r (r (a))))) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))) (uint64 (f (r (r (f (f (r (a))))))))) (sha256tree (c (q 7) (c (c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (r (a)))) (q ()))) (c (c (q 5) (c (c (q 20) (c (c (q 1) (c (f (r (r (r (f (f (r (a)))))))) (q ()))) (q ()))) (q ((q ()))))) (q ())))) (q ()))) (q ())))) (q 0x0000000000000000)) (q ()))) (f (r (r (r (r (a)))))))) (q ()))))))))) (q (f (r (r (r (r (a)))))))) (a))))(c (f (r (r (r (r (r (r (a)))))))) (c (sha256 (sha256 (f (f (r (a)))) (sha256tree (c (q 7) (c (c (q 5) (c (c (q 1) (c (f (r (f (r (a))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (a)) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))) (uint64 (f (r (r (f (r (a)))))))) (sha256tree (c (q 7) (c (c (q 5) (c (c (q 1) (c (sha256tree (f (r (r (r (a)))))) (q ()))) (c (c (c (q 5) (c (c (q 1) (c (f (a)) (q ()))) (q ((a))))) (q ())) (q ())))) (q ())))) (uint64 (f (r (r (a)))))) (c (f (a)) (q (())))))))))"

        compare_sums = f"((c (q ((c (f (a)) (a)))) (c (q ((c (i (f (r (a))) (q ((c (f (a)) (c (f (a)) (c (r (f (r (a)))) (c (+ (f (r (r (f (f (r (a))))))) (f (r (r (a))))) (c (+ (f (r (r (r (f (f (r (a)))))))) (f (r (r (r (a)))))) (q ())))))))) (q (= (f (r (r (a)))) (f (r (r (r (a)))))))) (a)))) (c (f (r (r (r (r (r (r (a)))))))) (q (() ()))))))"

        aggregator_code_path = f"((c (i (f (r (r (r (r (r (r (a)))))))) (q ((c (i {compare_sums} (q {consume_es_generate_as}) (q (x))) (a)))) (q (q ()))) (a)))"

        normal_case = f"(c {consume_a} (c {create_e} (c {assert_my_parent_follows_core_logic} {self.merge_two_lists(replace_generated_createcoins, aggregator_code_path)})))"

        create_child_with_my_puzzle = f"(c (q 51) (c (sha256tree {add_core_to_my_innerpuz_reveal}) (c (uint64 (f (r (r (a))))) (q ()))))"
        eve_case = f"((c (i (= (q 0x{originID}) (f (r (a)))) (q (c {assert_my_parent_is_origin} (c {create_child_with_my_puzzle} (q ())))) (q (x))) (a)))"
        core = f"((c (i (l (f (r (a)))) (q {normal_case}) (q {eve_case} ) ) (a)))"
        breakpoint()
        return core

    # This is for spending a recieved coloured coin
    def cc_make_solution(self, core, parent_info, amount, innerpuzreveal, innersol, aggregator, aggregatees=None):
        parent_str = ""
        # parent_info is a triplet or the originID
        # genesis coin isn't coloured, child of genesis uses originID, all subsequent children use triplets
        # aggregator is (primary_input, innerpuzzlehash, amount)
        # aggregatees is list of [(primary_input, innerpuzhash, coin_amount, output_amount)]
        if isinstance(parent_info, tuple):
            #  (parent primary input, parent inner puzzle hash, parent amount)
            parent_str = f"(0x{parent_info[0]} 0x{parent_info[1]} {parent_info[2]})"
        else:
            parent_str = f"0x{parent_info.hex()}"

        aggregator_formatted = "()"
        if aggregator is not None:
            aggregator_formatted = f"(0x{aggregator[0]} 0x{aggregator[1]} {aggregator[2]})"

        aggees = "("
        if aggregatees is not None:
            for aggregatee in aggregatees:
                aggees = aggees + f"(0x{aggregatee[0]} 0x{aggregatee[1]} {aggregatee[2]} {aggregatee[3]})"
        aggees = aggees + ")"

        sol = f"({core} {parent_str} {amount} {innerpuzreveal} {innersol} {aggregator_formatted} {aggees})"
        print(f"DEBUG solstring: {sol}")
        return Program(binutils.assemble(sol))

    # This is for spending a recieved coloured coin
    def cc_generate_signed_transaction(self, coin, parent_info, amount, innersol, aggregator, aggregator_innerpuzhash,aggregatees=None, sigs=[]):
        innerpuz = binutils.disassemble(self.my_coloured_coins[coin][0])

        core = self.my_coloured_coins[coin][1]
        temp_fix_innersol = clvm.to_sexp_f([innersol, []])
        aggregator_info = (aggregator.parent_coin_info, aggregator_innerpuzhash, aggregator.amount)
        solution = self.cc_make_solution(core, parent_info, amount, innerpuz, binutils.disassemble(temp_fix_innersol), aggregator_info, None)
        solution_list = CoinSolutionList([CoinSolution(coin, clvm.to_sexp_f([self.cc_make_puzzle(ProgramHash(self.my_coloured_coins[coin][0]), core), solution]))])
        aggsig = BLSSignature.aggregate(sigs)
        spend_bundle = SpendBundle(solution_list, aggsig)
        return spend_bundle

    def create_puzzle_for_ephemeral(self, aggregator_coin, spend_amount):
        puzzle = f"(r (r (c (q 0x{aggregator_coin.name()}) (c (uint64 (q {spend_amount})) (q ())))))"
        return puzzle

    def create_puzzle_for_aggregator(self, aggregateeID):
        puzzle = f"(r (c (q 0x{aggregateeID}) (q ())))"
        return puzzle


"""
Copyright 2020 Chia Network Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
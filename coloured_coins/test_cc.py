# this is used to iterate on `lock_coins.clvm` to ensure that it's producing the sort
# of output that we expect

import binascii
import hashlib
import io

from clvm import to_sexp_f, KEYWORD_FROM_ATOM

from clvm.serialize import sexp_from_stream

from clvm_tools.binutils import disassemble as bu_disassemble, assemble
from clvm_tools.clvmc import compile_clvm
from clvm_tools.curry import curry

from stages.stage_0 import run_program

KFA = {
    50: "AGG_SIG",
    51: "CREATE_COIN",
    52: "ASSERT_COIN_CONSUMED",
    53: "ASSERT_MY_COIN_ID",
    54: "ASSERT_TIME_EXCEEDS",
    55: "ASSERT_BLOCK_INDEX_EXCEEDS",
    56: "ASSERT_BLOCK_AGE_EXCEEDS",
    57: "AGG_SIG_ME",
    58: "ASSERT_FEE",
}


CONDITIONS = {v: k for k, v in KFA.items()}


def sha256(args):
    h = hashlib.sha256()
    for _ in args.as_iter():
        atom = _.as_atom()
        h.update(atom)
    return h.digest()


def sha256tree(v, literals=[]):
    if v.listp():
        left = sha256tree(v.first(), literals)
        right = sha256tree(v.rest(), literals)
        s = b"\2" + left + right
    else:
        atom = v.as_atom()
        if atom in literals:
            return atom
        s = b"\1" + atom
    return hashlib.sha256(s).digest()


def disassemble(sexp):
    kfa = dict(KEYWORD_FROM_ATOM)
    kfa.update((to_sexp_f(k).as_atom(), v) for k, v in KFA.items())
    return bu_disassemble(sexp, kfa)


def load_clvm(path, search_paths):
    output = f"{path}.hex"
    compile_clvm(path, output, search_paths=search_paths)
    h = open(output).read()
    b = binascii.unhexlify(h)
    f = io.BytesIO(b)
    s = sexp_from_stream(f, to_sexp_f)
    return s


def cc_puzzle_for_inner_puzzle(mod_code, genesis_coin_hash, inner_puzzle):
    return curry(mod_code, [sha256tree(mod_code), genesis_coin_hash, inner_puzzle])


def cc_ph_for_inner_ph(mod_code, genesis_coin_hash, inner_ph):
    return sha256tree(
        curry(mod_code, [sha256tree(mod_code), genesis_coin_hash, inner_ph]), [inner_ph]
    )


def lock_ph_for_inputs(mod_code, genesis_coin_hash, input_coins):
    return b"LOCK_VALUE"


def solution_for_inputs(
    mod_code,
    genesis_coin_hash,
    input_coins,
    input_index,
    output_iph_amount_pairs,
    iph_for_cc_ph_f,
    coin_for_id_f,
):
    # returns condition list, [parent-proofs, input-proofs, output-proofs]
    conditions = []
    input_coin = input_coins[input_index]
    input_coin_id = sha256(to_sexp_f(input_coin))

    #
    conditions.append([CONDITIONS["ASSERT_MY_COIN_ID"], input_coin_id])

    # assert lock coin consumed
    lock_ph = lock_ph_for_inputs(mod_code, genesis_coin_hash, input_coins)
    lock_coin = [input_coin_id, lock_ph, 0]
    lock_coin_id = sha256(to_sexp_f(lock_coin))
    # conditions.append([CONDITIONS["ASSERT_COIN_CONSUMED"], lock_coin_id])

    # create lock coin
    conditions.append([CONDITIONS["CREATE_COIN"], lock_ph, 0])

    proofs = []
    parent_proofs = []
    proofs.append(parent_proofs)

    input_proofs = []
    proofs.append(input_proofs)
    output_proofs = [0]
    proofs.append(output_proofs)

    if input_index == 0:
        # build proofs and additions conditions

        for input_coin in input_coins:
            input_ph = input_coin[1]
            input_iph = iph_for_cc_ph_f(input_ph)
            input_proofs.append(input_iph)

            parent_coin = coin_for_id_f(input_coin[0])
            if parent_coin:
                parent_ph = parent_coin[1]
                parent_iph = iph_for_cc_ph_f(parent_ph)
                parent_proofs.append(parent_iph)
            else:
                parent_proofs.append(0)

        for ph, amount in output_iph_amount_pairs:
            output_ph = cc_ph_for_inner_ph(mod_code, genesis_coin_hash, ph)
            condition = [CONDITIONS["CREATE_COIN"], output_ph, amount]
            conditions.append(condition)
            output_proofs.append(ph)
    return conditions, proofs


def main():
    mod_code = load_clvm(
        "cc.clvm",
        search_paths=[
            "/Users/kiss/projects/chia/wallets/ccv2/venv/src/clvm-tools/clvm_runtime"
        ],
    )

    genesis_puzzle_hash = assemble("1")  # return the solution verbatim
    genesis_coin = [b"GENESIS", genesis_puzzle_hash, 100000]

    prog = mod_code
    genesis_coin_hash = sha256(to_sexp_f(genesis_coin))

    inner_puzzle = assemble("1")
    inner_puzzle_hash = sha256tree(inner_puzzle)

    input_coins = [
        [genesis_coin_hash, inner_puzzle_hash, 500],
        [genesis_coin_hash, inner_puzzle_hash, 1500],
        [genesis_coin_hash, inner_puzzle_hash, 2501],
    ]

    cc_puzzle = cc_puzzle_for_inner_puzzle(mod_code, genesis_coin_hash, inner_puzzle)
    cc_puzzle_hash = sha256tree(cc_puzzle)
    print(f"cc_puzzle_hash = {cc_puzzle_hash.hex()}")

    prog = cc_puzzle

    dest_inner_puzzle = to_sexp_f(1)
    dest_inner_ph = sha256tree(dest_inner_puzzle)

    dest_inner_ph_2 = sha256tree(to_sexp_f(2))
    dest_puzzle = cc_puzzle_for_inner_puzzle(
        mod_code, genesis_coin_hash, dest_inner_puzzle
    )
    dest_ph = sha256tree(dest_puzzle)

    output_iph_amount_pairs = [
        [dest_inner_ph, 4500],
        [dest_inner_ph_2, 1],
    ]

    COINS = []
    coins_dict = dict((sha256(to_sexp_f(_)), _) for _ in COINS)

    IPH = [inner_puzzle_hash]
    ph_to_iph_dict = dict(
        (cc_ph_for_inner_ph(mod_code, genesis_coin_hash, _), _) for _ in IPH
    )

    for input_index in range(3):
        inner_puzzle_solution, proofs = solution_for_inputs(
            mod_code,
            genesis_coin_hash,
            input_coins,
            input_index,
            output_iph_amount_pairs,
            ph_to_iph_dict.get,
            coins_dict.get,
        )

        my_id = sha256(to_sexp_f(input_coins[input_index]))

        solution = [input_coins, inner_puzzle_solution, input_index]
        solution.extend(proofs)
        solution = to_sexp_f(solution)
        args = solution
        print(f"\nbrun -y main.sym '{bu_disassemble(prog)}' '{bu_disassemble(args)}'")
        cost, r = run_program(prog, args)
        print(disassemble(r))

    for _ in range(0):
        parent_coin_id = sha256(to_sexp_f(input_coins[_]))
        my_coin_id = sha256(to_sexp_f([parent_coin_id, cc_puzzle_hash, 0]))
        print(f"my_coin_id[{_}] = {my_coin_id.hex()}")


if __name__ == "__main__":
    main()

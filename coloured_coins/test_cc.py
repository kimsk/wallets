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


def sha256(args):
    h = hashlib.sha256()
    for _ in args.as_iter():
        atom = _.as_atom()
        h.update(atom)
    return h.digest()


def sha256tree(v):
    if v.listp():
        left = sha256tree(v.first())
        right = sha256tree(v.rest())
        s = b"\2" + left + right
    else:
        atom = v.as_atom()
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


def cc_puzzle_for_inner_puzzle(mod_code, genesis, inner_puzzle):
    return curry(mod_code, [mod_code, genesis, inner_puzzle])


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

    list_of_input_coins = [
        [genesis_coin_hash, inner_puzzle_hash, 500],
        [genesis_coin_hash, inner_puzzle_hash, 1500],
        [genesis_coin_hash, inner_puzzle_hash, 2500],
    ]

    cc_puzzle = cc_puzzle_for_inner_puzzle(mod_code, genesis_coin_hash, inner_puzzle)
    cc_puzzle_hash = sha256tree(cc_puzzle)
    print(f"cc_puzzle_hash = {cc_puzzle_hash.hex()}")

    prog = cc_puzzle

    for input_index in range(3):
        my_id = sha256(to_sexp_f(list_of_input_coins[input_index]))
        dest_ph = bytes([4]) * 32
        coin_value = 500 + 1000 * input_index
        if input_index == 0:
            inner_puzzle_solution = assemble(f"((51 LOCK_VALUE 0) (53 0x{my_id.hex()}) (51 0x{dest_ph.hex()} {coin_value}))")
        else:
            inner_puzzle_solution = assemble(f"((51 LOCK_VALUE 0) (53 0x{my_id.hex()}) (51 0x{dest_ph.hex()} {coin_value}))")
        solution = to_sexp_f([list_of_input_coins[input_index:input_index+1], inner_puzzle_solution, 0, [0], []])
        args = solution
        print(f"\nbrun -y main.sym '{disassemble(prog)}' '{disassemble(args)}'")
        cost, r = run_program(prog, args)
        print(disassemble(r))

    for _ in range(0):
        parent_coin_id = sha256(to_sexp_f(list_of_input_coins[_]))
        my_coin_id = sha256(to_sexp_f([parent_coin_id, cc_puzzle_hash, 0]))
        print(f"my_coin_id[{_}] = {my_coin_id.hex()}")

    print(f"\nbrun -y main.sym '{disassemble(prog)}' '{disassemble(args)}'")


if __name__ == "__main__":
    main()

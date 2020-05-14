import pkg_resources
import os
import sys

from chiasim.hashable import Program
from clvm_tools.clvmc import compile_clvm


def path_list_for_filename(filename):
    yield pkg_resources.resource_filename(__name__, filename)
    yield "%s/%s.hex" % (sys.prefix, filename)


def load_clvm(filename):
    for p in path_list_for_filename(filename):
        if os.path.isfile(p):
            break

    output = p + '.hex'
    compile_clvm(p, output)

    clvm_hex = open(output, "rt").read()
    clvm_blob = bytes.fromhex(clvm_hex)
    return Program.from_bytes(clvm_blob)

# Modified from https://github.com/gnmartins/assert-p4

#!/usr/bin/env python3

import json
import sys
import Node
import class_translation
import re

from os.path import splitext, basename
from optparse import OptionParser
import argparse
import argcomplete
from argcomplete.completers import FilesCompleter

def main(args):
    with open(args.p4_json) as data_file:
        program = json.load(data_file)

    model = class_translation.run(Node.NodeFactory(program), args)
    model = class_translation.post_processing(model)

    #Print output to file
    if not args.outfile:
        p4_program_name = splitext(basename(args.p4_json))[0]
        assert_p4_outfile = "{}.java".format(p4_program_name)
    else:
        assert_p4_outfile = "{}.java".format(args.outfile)

    with open(assert_p4_outfile, "w") as output:
        output.write(model)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", dest="p4_json", metavar="FILE", type=str,
            help="input p4 IR json file").completer = FilesCompleter()
    parser.add_argument("-o", "--output", dest="outfile", metavar="FILE", type=str,
            help="specify output file name").completer = FilesCompleter()
    parser.add_argument("--verbose", dest="verbose",
            action="store_true", default=False)

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not args.p4_json:
        parser.error("missing input P4-IR json file")

    main(args)

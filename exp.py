#!/usr/local/bin/python3.9
from common.init_palace import main
import argparse

MAIN_SCRIPT_FILE = "model/main.js"

parser = argparse.ArgumentParser()
parser.add_argument('app', help='target application')
parser.add_argument('-b', '--breakpoint', help='set breakpoint')
parser.add_argument('-s', '--spawn-model',
                    action='store_true', help='launch spawn model')
parser.add_argument('-l', '--load', default=MAIN_SCRIPT_FILE,
                    help='load custom script')

args = parser.parse_args()

if not args.breakpoint is None:
    if len(format_breakpoint(args.breakpoint)) == 0:
        print(RED("set breakpoint parameter type mismatch, ") +
              GREEN("E.g -> '-b lib**.so!0x***'"))
        exit(0)

main(args)

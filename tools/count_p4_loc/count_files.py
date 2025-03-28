import os
from optparse import OptionParser

target_files = set()

def get_include_files(file_name, options):
    global target_files

    with open(file_name, 'r') as fp:
        do_ignore_lines = False
        for count, line in enumerate(fp):
            if line.strip().startswith('#ifdef '):
                macro_txt = line.strip()[len('#ifdef'):].strip()
                if macro_txt != 'WITH_UPF' and macro_txt != 'WITH_INT':
                    continue

                if macro_txt not in options.flags:
                    do_ignore_lines = True

            if line.strip().startswith('#endif'):
                do_ignore_lines = False

            if do_ignore_lines:
                continue

            if line.strip().startswith('#include "'):
                line_words = line.split('"')

                for include_dir in options.include_dirs:
                    file_name = f'{include_dir}/{line_words[1]}'
                    if os.path.isfile(file_name):
                        include_file = os.path.abspath(file_name)
                        if include_file not in target_files:
                            print(f'Includes {line_words[1]}')
                            target_files.add(include_file)
                            get_include_files(include_file, options)

def count_files(options):
    global target_files

    get_include_files(options.input, options)
    target_files.add(options.input)

    total_counts = 0
    for target_file in target_files:
        with open(target_file, 'r') as fp:
            do_ignore_lines = False
            ignore_line_cnt = 0
            for count, line in enumerate(fp):

                if do_ignore_lines:
                    ignore_line_cnt += 1
                    if line.strip().startswith('#endif'):
                        do_ignore_lines = False
                        continue

                if line.strip().startswith('#ifdef '):
                    macro_txt = line.strip()[len('#ifdef'):].strip()
                    if macro_txt != 'WITH_UPF' and macro_txt != 'WITH_INT':
                        continue

                    if macro_txt not in options.flags:
                        do_ignore_lines = True
                        ignore_line_cnt += 1

            file_line_cnt = count + 1 - ignore_line_cnt
            print(f'Total Number of lines {target_file}:', file_line_cnt)
            total_counts += file_line_cnt

    print(f'Total:', total_counts)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input",
            help="input P4 file to count", metavar="FILE")
    parser.add_option("-I", action="append", type="string",
            dest="include_dirs", metavar="DIR", default=[],
            help="specify include directories")
    parser.add_option("-D", action="append", type="string",
            dest="flags", metavar="FLAG", default=[],
            help="add flags")

    (options, args) = parser.parse_args()

    count_files(options)


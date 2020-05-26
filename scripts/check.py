#!/usr/bin/python3

# Author: Luca Piccolboni (piccolboni@cs.columbia.edu)
# This script checks if some cryptographic rules are violated or not.

import os
import re
import sys
import time
import zxcvbn
import binascii
import argparse
import traceback
import subprocess
import shutil

###############################################################################
# Common functions
###############################################################################


def run_cmd(cmd):

    split = cmd.split(" ")

    try:

        # Return the full standard output
        return subprocess.check_output(split, stderr=subprocess.STDOUT).decode("utf-8")

    except subprocess.CalledProcessError as e:

        print(e.output.decode("utf-8"))

        # Just return an error string
        return str("Error")


def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


###############################################################################
# Print Utilities
###############################################################################


def function_name():

    # Return the name of the calling check function
    return traceback.extract_stack(None, 3)[0][2][6:]


def print_verbose(args, message):

    if args.verbose:
        args.out_file.write(message)


def print_start(args):

    print_verbose(args, function_name() + "\n")


def print_result(args, fail):

    if fail == 0:
        args.out_file.write(function_name() + ": RESPECTED\n")
    elif fail == 1:
        args.out_file.write(function_name() + ": VIOLATED\n")
    else:  # fail == -1
        args.out_file.write(function_name() + ": SKIPPED\n")

    return fail

###############################################################################
# Search Utilities
###############################################################################


def search_string_in_file(string, content, start=0):

    pos = content.lower().find(string.lower(), start)

    if pos == -1:
        return 0

    return pos


def search_regexp_in_file(reg, content, start=0):

    pattern = re.compile(reg.lower())
    return pattern.search(content.lower(), start)


def collect_all_values(string, content, hexa=False):

    start = 0
    res = set()

    while True:

        pos1 = search_string_in_file(string, content, start)
        if pos1 == 0:
            break

        pos2 = search_string_in_file("\n", content, pos1)
        if pos2 == 0:
            break

        value = content[pos1 + len(string): pos2]
        if hexa:

            try:

                conv = int(value.strip(), 16)
                res.add(value.strip())

            except ValueError as e:

                # insert only hexadecimal string
                pass

        else:

            res.add(value.strip())

        start = pos2 + 1

    return res


def collect_all_values_regexp(exp, content):

    start = 0
    res = set()

    while True:

        pos1 = search_regexp_in_file(exp, content, start)
        if not pos1:
            break

        string = pos1.group(0)

        pos2 = search_string_in_file("\n", content, pos1.start(0))
        if pos2 == 0:
            break

        value = content[pos1.start(0) + len(string): pos2]
        res.add(value.strip())
        start = pos2 + 1

    return res


def collect_all_duplicated_values(string, content):

    start = 0
    seen = set()
    dupl = set()

    while True:

        pos1 = search_string_in_file(string, content, start)
        if pos1 == 0:
            break

        pos2 = search_string_in_file("\n", content, pos1)
        if pos2 == 0:
            break

        val = content[pos1 + len(string): pos2].strip()
        if val in seen:
            dupl.add(val)

        seen.add(val)
        start = pos2 + 1

    return dupl


def collect_all_duplicate_pairs(string1, string2, content):

    start = 0
    seen = set()
    dupl = set()

    while True:

        pos1 = search_string_in_file(string1, content, start)
        if pos1 == 0:
            break

        pos2 = search_string_in_file("\n", content, pos1)
        if pos2 == 0:
            break

        pos3 = search_string_in_file(string2, content, pos2)
        if pos3 == 0:
            break

        pos4 = search_string_in_file("\n", content, pos3)
        if pos4 == 0:
            break

        val1 = content[pos1 + len(string1): pos2].strip()
        val2 = content[pos3 + len(string2): pos4].strip()

        if (val1, val2) in seen:
            dupl.add((val1, val2))

        seen.add((val1, val2))
        start = pos4 + 1

    return dupl


###############################################################################
# Random tests
###############################################################################

def random_tests(bitset):

    test_failed = 0
    test_passed = 0

    f = open("hexstream.bin", "wb")
    for string in bitset:
        if is_hex(string):
            f.write(binascii.unhexlify(string))
    f.close()

    summary_found = False
    output = run_cmd("python random-tests/sp800_22_tests.py hexstream.bin")
    for line in output.split("\n"):

        if "SUMMARY" in line:
            summary_found = True

        if summary_found:
            if "PASS" in line:
                test_passed = test_passed + 1
            else:  # FAIL
                test_failed = test_failed + 1

    os.remove("hexstream.bin")
    return (test_passed, test_failed)


def getUtilRandom(content):

    start = 0
    random = set()
    str1 = "[Random] next bytes: "

    while True:

        pos1 = search_string_in_file(str1, content, start)

        if pos1 == 0:
            break

        pos2 = search_string_in_file("\n", content, pos1)

        if pos2 == 0:
            break

        random.add(content[pos1 + len(str1): pos2].strip())

        start = pos2 + 1

    return random


def getSecureRandom(content):

    start = 0
    random = set()
    str1 = "[SecureRandom] next bytes: "

    while True:

        pos1 = search_string_in_file(str1, content, start)

        if pos1 == 0:
            break

        pos2 = search_string_in_file("\n", content, pos1)

        if pos2 == 0:
            break

        random.add(content[pos1 + len(str1): pos2].strip())

        start = pos2 + 1

    return random


###############################################################################
# Rule R-01
###############################################################################

insecure_hash_functions = ["MD2", "MD-2",
                           "MD4", "MD-4",
                           "MD5", "MD-5",
                           "SHA1", "SHA-1"]


def check_rule_R01(args):

    # Don't use insecure hash (e.g., MD2, MD4, SHA-1)

    fail = 0
    str1 = "[MessageDigest] algorithm: "

    print_start(args)

    for h in insecure_hash_functions:

        if search_string_in_file(str1 + h, args.in1_content):
            print_verbose(args, "\t Hash " + h + "\n")
            fail = 1

        if args.in2_content is not None:
            if search_string_in_file(str1 + h, args.in2_content):
                print_verbose(args, "\t Hash " + h + "\n")
                fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-02
###############################################################################


insecure_symm_encryption_functions = ["RC2", "RC-2",
                                      "RC4", "RC-4",
                                      "RC5", "RC-5",
                                      "DES", "DESede",
                                      "Blowfish", "IDEA",
                                      "3-KeyTripleDES"]


def check_rule_R02(args):

    # Don't use insecure algorithms (e.g., RC2, RC4, IDEA, ..)

    fail = 0
    str1 = "[Cipher] algorithm: "
    reg1 = "\[Cipher\] algorithm: PBEWith"

    print_start(args)

    for func in insecure_hash_functions:

        if search_regexp_in_file(reg1 + func + ".*", args.in1_content):
            print_verbose(args, "\t Hash " + func + "\n")
            fail = 1

        if args.in2_content is not None:
            if search_regexp_in_file(reg1 + func + ".*", args.in2_content):
                print_verbose(args, "\t Hash " + func + "\n")
                fail = 1

    # AES without operation mode (insecure)
    algs = collect_all_values(str1 + "AES", args.in1_content)
    for alg in algs:
        if alg == "":
            print_verbose(args, "\t Encr AES missing mode\n")
            fail = 1

    for func in insecure_symm_encryption_functions:

        if search_string_in_file(str1 + func, args.in1_content):
            print_verbose(args, "\t Encr " + func + "\n")
            fail = 1

        if args.in2_content is not None:
            if search_regexp_in_file(reg1 + ".*" + func, args.in2_content):
                print_verbose(args, "\t Hash " + func + "\n")
                fail = 1

            # AES without operation mode (insecure)
            algs = collect_all_values(str1 + "AES", args.in2_content)
            for alg in algs:
                if alg == "":
                    print_verbose(args, "\t Encr AES missing mode \n")
                    fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-03
###############################################################################


def check_rule_R03(args):

    # Don't use the operation mode ECB with > 1 block

    fail = 0
    str1 = "[Cipher] out bytes: "
    str2 = " with "
    str3 = "ECB"

    print_start(args)

    start = 0

    while True:

        pos1 = search_string_in_file(str1, args.in1_content, start)

        if pos1 == 0:
            break

        pos2 = search_string_in_file(str2, args.in1_content, pos1)

        if pos2 == 0:
            break

        pos3 = search_string_in_file("\n", args.in1_content, pos2)

        if pos3 == 0:
            break

        if search_string_in_file(str3, args.in1_content[pos1: pos3]):

            fin_bytes = args.in1_content[pos1 + len(str1): pos2].strip()

            if int(fin_bytes) > 16:
                print_verbose(args, "\t ECB bytes: " + fin_bytes + "\n")
                fail = 1
                break

        start = pos3 + 1

    if args.in2_content is not None:

        start = 0

        while True:

            pos1 = search_string_in_file(str1, args.in2_content, start)

            if pos1 == 0:
                break

            pos2 = search_string_in_file(str2, args.in2_content, pos1)

            if pos2 == 0:
                break

            pos3 = search_string_in_file("\n", args.in2_content, pos2)

            if pos3 == 0:
                break

            if search_string_in_file(str3, args.in2_content[pos1: pos3]):

                fin_bytes = args.in2_content[pos1 + len(str1): pos2].strip()

                if int(fin_bytes) > 16:
                    print_verbose(args, "\t ECB bytes: " + fin_bytes + "\n")
                    fail = 1
                    break

            start = pos3 + 1

    return print_result(args, fail)

###############################################################################
# Rule R-04
###############################################################################


def check_rule_R04(args):

    # Don't use the operation mode CBC if AES is used

    fail = 0
    str1 = "[Cipher] algorithm: AES/CBC/"

    print_start(args)

    if search_string_in_file(str1, args.in1_content):
        print_verbose(args, "\t AES/CBC detected\n")
        fail = 1

    if args.in2_content is not None:
        if search_string_in_file(str1, args.in2_content):
            print_verbose(args, "\t AES/CBC detected\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-05
###############################################################################


def check_rule_R05(args):

    # Don't use a static (constant) key for encryption

    fail = 0
    str1 = "[Cipher] key.encoded: "

    print_start(args)

    if args.in2_content is None:
        return print_result(args, -1)

    keyset1 = collect_all_values(str1, args.in1_content, True)
    keyset2 = collect_all_values(str1, args.in2_content, True)

    if not keyset1.isdisjoint(keyset2):
        for key in keyset1.intersection(keyset2):
            print_verbose(args, "\t static key: " + key + "\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-06
###############################################################################


def check_rule_R06(args):

    # Don't use a 'badly-derived' key for encryption

    fail = 0
    str1 = "[Random] next: "
    str2 = "[SecureRandom] next: "
    str3 = "[Cipher] key.encoded: "

    print_start(args)

    badvalues = collect_all_values(str1, args.in1_content, True)
    goodvalues = collect_all_values(str2, args.in1_content, True)
    keyvalues = collect_all_values(str3, args.in1_content, True)

    potbadkeys = set()

    for key in keyvalues:

        if key in badvalues:
            print_verbose(args, "\t Key from util.Random\n")
            fail = 1
            break

        if key not in goodvalues:
            potbadkeys.add(key)

    if not fail and potbadkeys:

        passed, failed = random_tests(potbadkeys)
        print_verbose(args, "\t Tests failed: " + str(failed) + "\n")
        print_verbose(args, "\t Tests passed: " + str(passed) + "\n")
        if failed > 0:
            fail = 1

    if args.in2_content is not None:

        badvalues = collect_all_values(str1, args.in2_content, True)
        goodvalues = collect_all_values(str2, args.in2_content, True)
        keyvalues = collect_all_values(str3, args.in2_content, True)

        potbadkeys = set()

        for key in keyvalues:

            if key in badvalues:
                print_verbose(args, "\t Key from util.Random\n")
                fail = 1
                break

            if key not in goodvalues:
                potbadkeys.add(key)

        if not fail and potbadkeys:

            passed, failed = random_tests(potbadkeys)
            print_verbose(args, "\t Tests failed: " + str(failed) + "\n")
            print_verbose(args, "\t Tests passed: " + str(passed) + "\n")
            if failed > 0:
                fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-07
###############################################################################


def check_rule_R07(args):

    # Don't use a static (constant) initialization vector

    fail = 0
    str1 = "[Cipher] key.iv: "

    print_start(args)

    if args.in2_content is None:
        return print_result(args, -1)

    ivset1 = collect_all_values(str1, args.in1_content, True)
    ivset2 = collect_all_values(str1, args.in2_content, True)

    if not ivset1.isdisjoint(ivset2):
        for iv in ivset1.intersection(ivset2):
            print_verbose(args, "\t static iv: " + iv + "\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-08
###############################################################################


def check_rule_R08(args):

    # Don't use a 'badly-derived' iv for encryption

    fail = 0
    str1 = "[Random] next: "
    str2 = "[SecureRandom] next: "
    str3 = "[Cipher] key.iv: "

    print_start(args)

    badvalues = collect_all_values(str1, args.in1_content, True)
    goodvalues = collect_all_values(str2, args.in1_content, True)
    ivvalues = collect_all_values(str3, args.in1_content, True)

    potbadivs = set()

    for iv in ivvalues:

        if iv in badvalues:
            print_verbose(args, "\t Key from util.Random\n")
            fail = 1
            break

        if iv not in goodvalues:
            potbadivs.add(iv)

    if not fail and potbadivs:

        passed, failed = random_tests(potbadivs)
        print_verbose(args, "\t Tests failed: " + str(failed) + "\n")
        print_verbose(args, "\t Tests passed: " + str(passed) + "\n")
        if failed > 0:
            fail = 1

    if args.in2_content is not None:

        badvalues = collect_all_values(str1, args.in2_content, True)
        goodvalues = collect_all_values(str2, args.in2_content, True)
        ivvalues = collect_all_values(str3, args.in2_content, True)

        potbadivs = set()

        for iv in ivvalues:

            if iv in badvalues:
                print_verbose(args, "\t Key from util.Random\n")
                fail = 1
                break

            if iv not in goodvalues:
                potbadivs.add(iv)

        if not fail and potbadivs:

            passed, failed = random_tests(potbadivs)
            print_verbose(args, "\t Tests failed: " + str(failed) + "\n")
            print_verbose(args, "\t Tests passed: " + str(passed) + "\n")
            if failed > 0:
                fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-09
###############################################################################


def check_rule_R09(args):

    # Don't reuse the initialization vector and key pairs

    fail = 0
    start = 0
    str1 = "[Cipher] key.iv: "
    str2 = "[Cipher] key.encoded: "

    print_start(args)

    dupl = collect_all_duplicate_pairs(str1, str2, args.in1_content)

    if dupl:
        print_verbose(args, "\t Duplicated (key, iv)\n")
        fail = 1

    if args.in2_content is not None:

        dupl = collect_all_duplicate_pairs(str1, str2, args.in2_content)

        if dupl:
            print_verbose(args, "\t Duplicated (key, iv)\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-10
###############################################################################


def check_rule_R10(args):

    # Don't use a static (constant) salt for key derivation

    fail = 0
    str1 = "[PBEKeySpec] salt: "
    str2 = "[PBEParameterSpec] salt: "

    print_start(args)

    if args.in2_content is None:
        return print_result(args, -1)

    salt1a = collect_all_values(str1, args.in1_content, True)
    salt1b = collect_all_values(str2, args.in1_content, True)
    salt1a = salt1a.union(salt1b)

    salt2a = collect_all_values(str1, args.in2_content, True)
    salt2b = collect_all_values(str2, args.in2_content, True)
    salt2a = salt2a.union(salt2b)

    if not salt1a.isdisjoint(salt2a):
        print_verbose(args, "\t Static salts\n")
        fail = 1

    return print_result(args, fail)


###############################################################################
# Rule R-11
###############################################################################

def check_rule_R11(args):

    # Don't use a short salt (< 64 bits) for key derivation

    fail = 0
    str1 = "[PBEKeySpec] salt: "
    str2 = "[PBEParameterSpec] salt: "
    str3 = "[PBEKeySpec] PBEKeySpec(char[])"

    print_start(args)

    salts1 = collect_all_values(str1, args.in1_content, True)
    salts2 = collect_all_values(str2, args.in1_content, True)
    salts = salts1.union(salts2)

    for salt in salts:
        if len(salt.strip()) * 4 < 64:
            print_verbose(args, "\t Short salt: " + salt + "\n")
            fail = 1

    if search_string_in_file(str3, args.in1_content):
        print_verbose(args, "\t Short salt: N.A.\n")
        fail = 1

    if args.in2_content is not None:

        salts1 = collect_all_values(str1, args.in2_content, True)
        salts2 = collect_all_values(str2, args.in2_content, True)
        salts = salts1.union(salts2)

        for salt in salts:
            if len(salt.strip()) * 4 < 64:
                print_verbose(args, "\t Short salt: " + salt + "\n")
                fail = 1

        if search_string_in_file(str3, args.in2_content):
            print_verbose(args, "\t Short salt: N.A.\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-12
###############################################################################


def check_rule_R12(args):

    # Don't use the salt for different purposes

    fail = 0
    str1 = "[PBEKeySpec] salt: "
    str2 = "[PBEParameterSpec] salt: "

    print_start(args)

    dupl1 = collect_all_duplicated_values(str1, args.in1_content)
    dupl2 = collect_all_duplicated_values(str2, args.in1_content)
    dupl = dupl1.union(dupl2)

    if dupl:
        print_verbose(args, "\t Duplicated salt\n")
        fail = 1

    if args.in2_content is not None:

        dupl1 = collect_all_duplicated_values(str1, args.in2_content)
        dupl2 = collect_all_duplicated_values(str2, args.in2_content)
        dupl = dupl1.union(dupl2)

        if dupl:
            print_verbose(args, "\t Duplicated salt\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-13
###############################################################################


def check_rule_R13(args):

    # Don't use < 1000 iterations for key derivation

    fail = 0
    str1 = "[PBEKeySpec] iteration: "
    str2 = "[PBEParameterSpec] iteration: "
    str3 = "[PBEKeySpec] PBEKeySpec(char[])"

    print_start(args)

    iterations1 = collect_all_values(str1, args.in1_content)
    iterations2 = collect_all_values(str2, args.in1_content)
    iterations = iterations1.union(iterations2)

    for iteration in iterations:
        if int(iteration) < 1000:
            print_verbose(args, "\t Iterations: " + iteration + "\n")
            fail = 1

    if search_string_in_file(str3, args.in1_content):
        print_verbose(args, "\t Iterations: N.A.\n")
        fail = 1

    if args.in2_content is not None:

        iterations1 = collect_all_values(str1, args.in2_content)
        iterations2 = collect_all_values(str2, args.in2_content)
        iterations = iterations1.union(iterations2)

        for iteration in iterations:
            if int(iteration) < 1000:
                print_verbose(args, "\t Iterations: " + iteration + "\n")
                fail = 1

        if search_string_in_file(str3, args.in2_content):
            print_verbose(args, "\t Iterations: N.A.\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-14
###############################################################################


def check_rule_R14(args):

    # Don't use a weak password (score < 3) for PBE

    fail = 0
    str1 = "[PBEKeySpec] password: "
    str2 = "[KeyStore] password: "

    print_start(args)

    subnames = args.in_file_name1.split(".")

    passwords1 = collect_all_values(str1, args.in1_content)
    passwords2 = collect_all_values(str2, args.in1_content)
    passwords = passwords1.union(passwords2)

    for password in passwords:
        analysis_result = zxcvbn.zxcvbn(password)
        if int(analysis_result["score"]) < 3:
            print_verbose(args, "\t Weak: " + password + "\n")
            fail = 1

        for subname in subnames:
            if subname in password:
                print_verbose(args, "\t Weak: " + password + "\n")
                fail = 1

    if args.in2_content is not None:

        passwords1 = collect_all_values(str1, args.in2_content)
        passwords2 = collect_all_values(str1, args.in2_content)
        passwords = passwords1.union(passwords2)

        for password in passwords:
            analysis_result = zxcvbn.zxcvbn(password)
            if int(analysis_result["score"]) < 3:
                print_verbose(args, "\t Weak: " + password + "\n")
                fail = 1

            for subname in subnames:
                if subname in password:
                    print_verbose(args, "\t Weak: " + password + "\n")
                    fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-15
###############################################################################


def check_rule_R15(args):

    # Don't use NIST-black-listed passwords for PBE

    fail = 0
    str1 = "[PBEKeySpec] password: "
    str2 = "[KeyStore] password: "
    passwords = set()

    print_start(args)

    passwords1a = collect_all_values(str1, args.in1_content)
    passwords1b = collect_all_values(str2, args.in1_content)
    passwords = passwords.union(passwords1a)
    passwords = passwords.union(passwords1b)

    if args.in2_content is not None:

        passwords2a = collect_all_values(str1, args.in2_content)
        passwords2b = collect_all_values(str2, args.in2_content)
        passwords = passwords.union(passwords2a)
        passwords = passwords.union(passwords2b)

    with open("./passwords/xato-net-10-million-passwords.txt") as passfile:

        pwned_passwords = passfile.read()

        for password in passwords:
            if password in pwned_passwords:
                print_verbose(args, "\t Broken: " + password + "\n")
                fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-16
###############################################################################


def check_rule_R16(args):

    # Don't use a static (constant) password for PBE

    fail = 0
    str1 = "[PBEKeySpec] password: "

    print_start(args)

    if args.in2_content is None:
        return print_result(args, -1)

    pass1 = collect_all_values(str1, args.in1_content)
    pass2 = collect_all_values(str1, args.in2_content)

    if not pass1.isdisjoint(pass2):
        for passw in pass1.intersection(pass2):
            print_verbose(args, "\t Static password: " + passw + "\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-17
###############################################################################


def check_rule_R17(args):

    # Don't use a static (constant) seed for PRNG

    fail = 0
    str1 = "[SecureRandom] next: "

    print_start(args)

    if args.in2_content is None:
        return print_result(args, -1)

    seed1 = collect_all_values(str1, args.in1_content, True)
    seed2 = collect_all_values(str1, args.in2_content, True)

    if not seed1.isdisjoint(seed2):
        for seed in seed1.intersection(seed2):
            print_verbose(args, "\t Static seed: " + seed + "\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-18
###############################################################################


def check_rule_R18(args):

    # Don't use insecure PRNG (java.util.Random)

    fail = 0
    str1 = "[Random] Random() called"

    print_start(args)

    if search_string_in_file(str1, args.in1_content):
        fail = 1

    if args.in2_content is not None:
        if search_string_in_file(str1, args.in2_content):
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-19
###############################################################################


def check_rule_R19(args):

    # A1: Don't use a short key (< 2048 bits) for RSA

    fail = 0
    start = 0
    exp1 = "\[Cipher\] key.bits \(RSA.*\): "
    exp2 = "\[Signature\] key.bits \(.*withRSA.*\): "

    print_start(args)

    allbits1 = collect_all_values_regexp(exp1, args.in1_content)
    allbits2 = collect_all_values_regexp(exp2, args.in1_content)
    allbits = allbits1.union(allbits2)

    for bits in allbits:
        if int(bits) < 2048:
            print_verbose(args, "\t Bits: " + bits + "\n")
            fail = 1

    if args.in2_content is not None:

        allbits1 = collect_all_values_regexp(exp1, args.in2_content)
        allbits2 = collect_all_values_regexp(exp2, args.in2_content)
        allbits = allbits1.union(allbits2)

        for bits in allbits:
            if int(bits) < 2048:
                print_verbose(args, "\t Bits: " + bits + "\n")
                fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-20
###############################################################################


def check_rule_R20(args):

    # Don't use the textbook (raw) algorithm for RSA

    fail = 0
    exp1 = ".*RSA/.*/NoPadding"

    print_start(args)

    if search_regexp_in_file(exp1, args.in1_content):
        print_verbose(args, "\t RSA No Padding\n")
        fail = 1

    if args.in2_content is not None:

        if search_regexp_in_file(exp1, args.in2_content):
            print_verbose(args, "\t RSA No Padding\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-21
###############################################################################


def check_rule_R21(args):

    # Don't use the padding PKCS1Padding for RSA

    fail = 0
    exp1 = ".*RSA/.*/PKCS1Padding"

    print_start(args)

    if search_regexp_in_file(exp1, args.in1_content):
        print_verbose(args, "\t RSA PKCS1Padding\n")
        fail = 1

    if args.in2_content is not None:

        if search_regexp_in_file(exp1, args.in2_content):
            print_verbose(args, "\t RSA PKCS1Padding\n")
            fail = 1

    return print_result(args, fail)


###############################################################################
# Rule R-22
###############################################################################

def check_rule_R22(args):

    fail = 0
    str1 = "[URL] protocol: http:"

    print_start(args)

    if search_string_in_file(str1, args.in1_content):
        https = collect_all_values(str1, args.in1_content)
        for http in https:
            print_verbose(args, "\t link: " + http + "\n")
        fail = 1

    if args.in2_content is not None:

        if search_string_in_file(str1, args.in2_content):
            https = collect_all_values(str1, args.in2_content)
            for http in https:
                print_verbose(args, "\t link: " + http + "\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-23
###############################################################################


def check_rule_R23(args):

    # Don't use a static (constant) password for KeyStore

    fail = 0
    str1 = "[KeyStore] password: "

    print_start(args)

    if args.in2_content is None:
        return print_result(args, -1)

    pass1 = collect_all_values(str1, args.in1_content)
    pass2 = collect_all_values(str1, args.in2_content)

    if not pass1.isdisjoint(pass2):
        for passw in pass1.intersection(pass2):
            print_verbose(args, "\t Static pass:" + passw + "\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-24
###############################################################################


def check_rule_R24(args):

    # Don't verify the hostname for SSL connections

    fail = 0
    str1 = "[HttpsURLConnection] dummyverifier: true"

    print_start(args)

    if search_string_in_file(str1, args.in1_content):
        fail = 1

    if args.in2_content is not None:
        if search_string_in_file(str1, args.in2_content):
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-25
###############################################################################


def check_rule_R25(args):

    # Don't verify certificates for SSL connections

    fail = 0
    str1 = "[SSLContext] dummy checkClient: true"
    str2 = "[SSLContext] dummy checkServer: true"
    str3 = "[SSLContext] dummy acceptedIssuers: true"

    print_start(args)

    if search_string_in_file(str1, args.in1_content):
        print_verbose(args, "Dummy checkClient\n")
        fail = 1

    if search_string_in_file(str2, args.in1_content):
        print_verbose(args, "Dummy checkServer\n")
        fail = 1

    if search_string_in_file(str3, args.in1_content):
        print_verbose(args, "Dummy accIssuers\n")
        fail = 1

    if args.in2_content is not None:

        if search_string_in_file(str1, args.in2_content):
            print_verbose(args, "Dummy checkClient\n")
            fail = 1

        if search_string_in_file(str2, args.in2_content):
            print_verbose(args, "Dummy checkServer\n")
            fail = 1

        if search_string_in_file(str3, args.in2_content):
            print_verbose(args, "Dummy accIssuers\n")
            fail = 1

    return print_result(args, fail)

###############################################################################
# Rule R-26
###############################################################################


def check_rule_R26(args):

    # Don't verify hostnames for SSL connections

    fail = 0
    str1 = "[SSLSocketFactory] getDefault() called"
    str2 = "[HttpsURLConnection] getHostnameVerifier() called"
    str3 = "[HttpsURLConnection] getDefaultHostnameVerifier() called"

    print_start(args)

    if search_string_in_file(str1, args.in1_content):
        fail = 1

    if search_string_in_file(str2, args.in1_content):
        fail = 0

    if search_string_in_file(str3, args.in1_content):
        fail = 0

    if args.in2_content is not None and not fail:

        if search_string_in_file(str1, args.in2_content):
            fail = 1

        if search_string_in_file(str2, args.in2_content):
            fail = 0

        if search_string_in_file(str3, args.in2_content):
            fail = 0

    return print_result(args, fail)

###############################################################################
# Argument parser
###############################################################################


def get_parser():

    parser = argparse.ArgumentParser(prog="check")

    parser.add_argument("--work_dir", required=True, metavar="<path>",
                        help="the directory containing the crypto logs")
    parser.add_argument("--rule_id", required=False, metavar="<id>",
                        help="check only the rule specified by its ID")
    parser.add_argument("--verbose", required=False, action="store_true",
                        help="print additional information about rules")

    return parser

###############################################################################
# Main
###############################################################################


def main():

    parser = get_parser()
    args = parser.parse_args()

    args.work_dir = os.path.abspath(args.work_dir)

    for log_name in os.listdir(args.work_dir):

        if log_name.endswith("cryptolog"):

            args.in_file_name1 = os.path.join(args.work_dir, log_name + "")
            args.in_file_name2 = os.path.join(args.work_dir, log_name + "2")
            out_file_name = os.path.abspath(args.in_file_name1[:-9] + "rules")

            # Input file 1
            in1_file = open(args.in_file_name1, "r")
            args.in1_content = in1_file.read()
            in1_file.close()

            # Input file 2
            args.in2_content = None
            if os.path.exists(args.in_file_name2):
                in2_file = open(args.in_file_name2, "r")
                args.in2_content = in2_file.read()
                in2_file.close()

            # Output file
            args.out_file = open(out_file_name, "w")

            if args.rule_id:
                name = "check_rule_R" + args.rule_id
                globals()[name](args)  # calls check
            else:
                check_rule_R01(args)
                check_rule_R02(args)
                check_rule_R03(args)
                check_rule_R04(args)
                check_rule_R05(args)
                check_rule_R06(args)
                check_rule_R07(args)
                check_rule_R08(args)
                check_rule_R09(args)
                check_rule_R10(args)
                check_rule_R11(args)
                check_rule_R12(args)
                check_rule_R13(args)
                check_rule_R14(args)
                check_rule_R15(args)
                check_rule_R16(args)
                check_rule_R17(args)
                check_rule_R18(args)
                check_rule_R19(args)
                check_rule_R20(args)
                check_rule_R21(args)
                check_rule_R22(args)
                check_rule_R23(args)
                check_rule_R24(args)
                check_rule_R25(args)
                check_rule_R26(args)

            print("Violations reported in " + out_file_name)
            args.out_file.close()


if __name__ == "__main__":
    main()

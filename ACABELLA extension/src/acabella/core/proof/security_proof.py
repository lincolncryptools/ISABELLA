#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from acabella.core.common.utils import *
from sympy import *
from acabella.core.proof.proof_generation import *
from acabella.core.proof.proof_verification import *
from acabella.core.proof.ac17_correctness_checks import *
from acabella.core.common.encodings import *

init_printing(use_unicode=True)


# this helper function can generate encodings automatically using the encodings_helper
def generate_the_encodings_then_the_proofs(
    masterkey,
    special_s,
    benc,
    kenc_fixed,
    kenc_att,
    cenc_fixed,
    cenc_att,
    unknown,
    prefixes,
    nr_indexed_encodings,
):
    """
    This helper function can generate encodings automatically using the encodings_helper.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        benc (list): Public key encodings.
        kenc_fixed (list): Fixed key encodings.
        kenc_att (list): Attribute-dependent key encodings.
        cenc_fixed (list): Fixed ciphertext encodings.
        cenc_att (list): Attribute-dependent ciphertext encodings.
        unknown (list): List of unkonwn variables.
        prefixes (list): Prefixes utilized.
        nr_indexed_encodings (int): Indexed encodings.

    Returns:
        (list): Generated proofs.
    """
    att_range_key_1 = [1, 3]
    att_range_ct = [1, 2]

    benc = create_b_encoding([], benc, [1, 2, 3])
    cenc = create_ciphertext_encoding(
        cenc_fixed, cenc_att, special_s, att_range_ct, prefixes, nr_indexed_encodings
    )

    kenc = create_key_encoding(
        kenc_fixed, kenc_att, att_range_key_1, prefixes, nr_indexed_encodings, [1]
    )
    unknown2 = generate_unknown_variable_set(
        kenc, cenc, benc, att_range_ct, att_range_key_1
    )
    unknown = merge_lists(unknown, unknown2)

    generate_the_proofs(masterkey, special_s, kenc, cenc, benc, unknown)


# this function generates the proofs for the given encodings
def generate_the_proofs(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    This function generates the proofs for the given encodings.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): List of unkonwn variables.

    Returns:
        (list): Generated proofs.
    """

    process_log = []

    (correct, kenc, cenc) = correct_form_silent(kenc, cenc, benc, unknown)
    if correct:
        # print("\n== Generating a security proof for the following encodings: ==\n")
        process_log.append(
            "\n== Generating a security proof for the following encodings: ==\n"
        )
        # pprint("\t\tMPK encodings: \t\t\t" + str(benc) + "\n", use_unicode=True)
        process_log.append("\t\tMPK encodings: \t\t\t" + str(benc) + "\n")
        # pprint("\t\tKey encodings: \t\t\t" + str(kenc) + "\n", use_unicode=True)
        process_log.append("\t\tKey encodings: \t\t\t" + str(kenc) + "\n")
        # pprint("\t\tCiphertext encodings: \t" + str(cenc) + "\n", use_unicode=True)
        process_log.append("\t\tCiphertext encodings: \t" + str(cenc) + "\n")
        output = generate_proof_selective(
            masterkey, special_s, kenc, cenc, benc, unknown
        )
        output = normalize_substitutions(masterkey, special_s, output)
        if output[0] != None:
            # print("\n The selective proof: \n")
            process_log.append("\n The selective proof: \n")

            # to latex
            # pprint(output, use_unicode=True)
            process_log.append(output)
            result, log = verify_proof(masterkey, special_s, kenc, cenc, benc, output)
            process_log.append(log)
            if result:
                # print("\n The selective proof verifies correctly. \n")
                process_log.append("\n The selective proof verifies correctly. \n")
            else:
                # print("\n [!] The selective proof does *not* verify correctly! \n")
                process_log.append(
                    "\n [!] The selective proof does *not* verify correctly! \n"
                )
        else:
            # print("\n No selective proof found.\n")
            process_log.append("\n No selective proof found.\n")

        output2 = generate_proof_co_selective(
            masterkey, special_s, kenc, cenc, benc, unknown
        )
        output2 = normalize_substitutions(masterkey, special_s, output2)
        if output2[0] != None:
            # print("\n The co-selective proof: \n")
            process_log.append("\n The co-selective proof: \n")

            # to latex
            # pprint(output2, use_unicode=True)
            process_log.append(output2)
            result, log = verify_proof(masterkey, special_s, kenc, cenc, benc, output2)
            process_log.append(log)
            if result:
                # print("\n The co-selective proof verifies correctly. \n")
                process_log.append("\n The co-selective proof verifies correctly. \n")
            else:
                # print("\n [!] The co-selective proof does *not* verify correctly! \n")
                process_log.append(
                    "\n [!] The co-selective proof does *not* verify correctly! \n"
                )
        else:
            # print("\n No co-selective proof found.\n")
            process_log.append("\n No co-selective proof found.\n")

        return process_log


# this function generates the proofs for the given encodings
def generate_the_proofs_ven23(masterkey, special_s, kenc, cenc, benc, unknown):

    print("\tGENERATE THE PROOFS VEN23 - STARTS HERE")

    process_log = []

    output = generate_proof_selective_ven23(
        masterkey, special_s, kenc, cenc, benc, unknown
    )
    output = normalize_substitutions_ven23(masterkey, special_s, output)
    if output[0] != None:
        # print("\n The selective proof: \n")
        process_log.append("\n The selective proof: \n")

        # to latex
        # pprint(output, use_unicode=True)
        process_log.append(output)
        result, log = verify_proof_ven23(masterkey, special_s, kenc, cenc, benc, output)
        process_log.append(log)
        if result:
            process_log.append("\n The selective proof verifies correctly. \n")
        else:
            process_log.append(
                "\n [!] The selective proof does *not* verify correctly! \n"
            )

        # TODO: co-selective

        return process_log


if __name__ == "__main__":

    # Wat11

    # these are fixed in the system
    att_mpk_group = parse_expr("att_mpk_group")
    att_scalar = parse_expr("att_scalar")
    policy_share = parse_expr("lambda_policy_share")

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, b2, r, rp, x, y, s, sp"
    )

    k1 = alpha + r * b
    k2 = r * att_mpk_group
    k3 = r
    c1 = policy_share * b + get_indexed_encoding("sp", 1) * att_mpk_group
    c2 = s
    c3 = get_indexed_encoding("sp", 1)
    mpk1 = b

    # known values: x, y

    unknown = []

    k_fixed = [k1, k3]
    k_att = [k2]
    c_fixed = [c2]
    c_att = [c1, c3]
    mpk = [mpk1]

    # generate_the_proofs(alpha, s, k, c, mpk, unknown)

    generate_the_encodings_then_the_proofs(
        alpha, s, mpk, k_fixed, k_att, c_fixed, c_att, unknown, ["sp"], 1
    )

    # Wat11 (not generated automatically)

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2 = symbols(
        "alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2"
    )

    k1 = alpha + r * b
    k2 = r * b0
    k3 = r
    k4 = r * b1
    c1 = s * b - s1 * b + sp * b1
    c2 = s
    c3 = sp
    c4 = s1 * b + sp * b2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = 1
    mpk5 = b2

    unknown = [alpha, b, b0, b1, b2, r, s, s1, sp]

    k = [k1, k2, k3, k4]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk5]

    generate_the_proofs(alpha, s, k, c, mpk, unknown)

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

init_printing(use_unicode=True)

"""ac17_correctness_checks.py: Methods for checking if an 
ABE scheme is correct according to the AC17 framework."""


def correct_form(kenc, cenc, benc, unknown):
    """
    Main function that calls the correctness checks for the AC17 form.

    Parameters:
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): Analysis result.
        (list): Key encodings.
        (list): Ciphertext encodings.
        (str): Process log.
    """

    process_log = []

    (result_k, message_k, kenc) = kenc_correct_form(kenc, benc, unknown)
    (result_c, message_c, cenc) = cenc_correct_form(cenc, benc, unknown)
    if result_k and result_c:
        # print("\n The pair encoding scheme satisfies the AC17 form. " + message_k + message_c + "\n")
        process_log.append(
            "\n The pair encoding scheme satisfies the AC17 form. "
            + message_k
            + message_c
            + "\n"
        )
        return (True, kenc, cenc, "\n".join(process_log))
    else:
        # print("\n The pair encoding scheme does not satisfy the AC17 form, because \n")
        process_log.append(
            "\n The pair encoding scheme does not satisfy the AC17 form, because \n"
        )
        if not result_k:
            # print(message_k)
            process_log.append(message_k)
        if not result_c:
            # print(message_c)
            process_log.append(message_c)
        return (False, None, None, "\n".join(process_log))


def correct_form_silent(kenc, cenc, benc, unknown):
    """
    The same as the correct_form function, without system messages.

    Parameters:
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): Analysis result.
        (list): Key encodings.
        (list): Ciphertext encodings.
    """
    (result_k, message_k, kenc) = kenc_correct_form(kenc, benc, unknown)
    (result_c, message_c, cenc) = cenc_correct_form(cenc, benc, unknown)
    if result_k and result_c:
        return (True, kenc, cenc)
    else:
        return (False, None, None)


def kenc_correct_form(kenc, benc, unknown):
    """
    Checks correctness of the key encoding.

    Parameters:
        kenc (list): Key encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (function): enc_correct_form.
    """
    return enc_correct_form(kenc, benc, unknown, "key")


def cenc_correct_form(cenc, benc, unknown):
    """
    Checks correctness of the ciphertext encoding.

    Parameters:
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (function): enc_correct_form.
    """
    return enc_correct_form(cenc, benc, unknown, "ciphertext")


def enc_correct_form(cenc, benc, unknown, mes):
    """
    Checks whether the encoding is of the correct form.

    Parameters:
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (bool): Analysis result.
    """
    cenc = canonical(cenc)
    s_nonlone = []
    for c in cenc:
        uvector = []
        writepolyasprod(c, uvector, unknown)
        if len(uvector) == 1:
            mono = uvector[0]
            lis = []
            recovervars(mono, lis)
            if len(lis) == 1:
                if type(mono) != int and not mono in benc:
                    s_nonlone.append(mono)

    lones_in_disguise = []
    associated_commons = []
    for c in cenc:
        uvector = []
        writepolyasprod(c, uvector, unknown)
        if len(uvector) > 1:
            for mono in uvector:
                if type(mono) != int:
                    lis = []
                    recovervars(mono, lis)
                    is_prod_with_benc = False
                    for var in lis:
                        if var in benc:
                            is_prod_with_benc = True
                    if is_prod_with_benc:
                        for var in lis:
                            if not var in benc and not var in s_nonlone:
                                lis.remove(var)
                                if var in lones_in_disguise:
                                    ind = lones_in_disguise.index(var)
                                    associated_commons[ind] = merge_lists(
                                        lis, associated_commons[ind]
                                    )
                                else:
                                    lones_in_disguise.append(var)
                                    associated_commons.append(lis)

    message = ""
    replaced = False
    ctr = 0
    for var in lones_in_disguise:
        if len(associated_commons[ctr]) > 1:
            lones_in_disguise.remove(var)
            s_nonlone.append(var)
            message = (
                "The "
                + mes
                + " encoding contained non-lone variables that do not occur as a singleton.\n"
            )
        else:
            ctr2 = 0
            for c in cenc:
                cenc[ctr2] = c.subs(var * associated_commons[ctr][0], var)
                ctr2 += 1
                replaced = True
        ctr += 1

    if replaced:
        message += (
            "The "
            + mes
            + " encoding previously contained non-lone variables that act as lone variables. These have now been replaced by lone variables."
        )

    return_boolean = True

    for c in cenc:
        uvector = []
        writepolyasprod(c, uvector, unknown)
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono, lis)
                if len(lis) > 2:
                    return_boolean = False
                    message += (
                        "\t - The "
                        + mes
                        + " encoding has monomials with more than two unknown variables \n"
                    )
                    # return (False, "The " + mes + " encoding has monomials with more than two unknown variables \n", None)
    for c in cenc:
        uvector = []
        writepolyasprod(c, uvector, unknown)
        if len(uvector) > 1:
            is_polynomial = False
            for mono in uvector:
                if type(mono) != int:
                    lis = []
                    recovervars(mono, lis)
                    for var in lis:
                        if var in benc:
                            is_polynomial = True
            if is_polynomial:
                for mono in uvector:
                    if type(mono) != int:
                        lis = []
                        recovervars(mono, lis)
                        if len(lis) == 1:
                            if lis[0] in s_nonlone:
                                return_boolean = False
                                message += (
                                    "\t - The "
                                    + mes
                                    + " encoding contains non-lone variables that are also used as lone variables \n"
                                )
                                # return (False, "The " + mes +  " encoding contains non-lone variables that are also used as lone variables \n", None)
    return (return_boolean, message, cenc)


def blinding_value_correct_form(blindingval, kenc, cenc, benc, unknown):
    """
    This function determines whether the blinding value is of the form alpha * s

    Parameters:
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (bool): Analysis result.
        (Symbol): alpha.
        (Symbol): special_s.
    """
    uvector = []
    writepolyasprod(blindingval, uvector, unknown)
    if len(uvector) > 1 or len(uvector) == 0:
        return (False, None, None)

    lis_bv_vars = []
    recovervars(uvector[0], lis_bv_vars)

    if len(lis_bv_vars) != 2:
        return (False, None, None)

    bv_1 = lis_bv_vars[0]
    bv_2 = lis_bv_vars[1]

    lis_vars_kenc = recover_list_enc_vars(kenc, benc, unknown)
    lis_vars_cenc = recover_list_enc_vars(cenc, benc, unknown)

    is_correct_form = False
    if bv_1 in lis_vars_kenc and bv_2 in lis_vars_cenc:
        is_correct_form = True
        alpha = bv_1
        special_s = bv_2
    if bv_1 in lis_vars_cenc and bv_2 in lis_vars_kenc:
        is_correct_form = True
        alpha = bv_2
        special_s = bv_1

    if is_correct_form:
        return (True, alpha, special_s)
    else:
        return (False, None, None)


def all_enc_contains_no_fractions(kenc, cenc, unknown):
    """
    This function determines whether the key and ciphertext encodings contains
    no fractions. It returns True if the encodings contains no fractions.

    Parameters:
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        unknown (list): Unknown variables.

    Returns:
        (bool): Analysis result.
    """
    bool_1 = enc_contains_no_fractions(kenc, unknown)
    bool_2 = enc_contains_no_fractions(cenc, unknown)
    return bool_1 and bool_2


def enc_contains_no_fractions(enc, unknown):
    """
    This function determines whether the encoding contains no fractions.
    It returns True if the encodings contains no fractions.

    Parameters:
        enc (list): Key or ciphertext encodings.
        unknown (list): Unknown variables.

    Returns:
        (bool): Analysis result.
    """
    enc = canonical(enc)

    denoms = collect_denoms(enc, unknown)

    return len(denoms) == 0


def recover_list_enc_vars(enc, benc, unknown):
    """
    This function makes a list of all variables occurring in enc that do not
    occur in benc.

    Parameters:
        enc (list): Key or ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): List of variables.
    """
    (_, uvector) = writeencodingasprod(enc, unknown)
    lis = []
    for mono in uvector:
        sub_lis = []
        recovervars(mono, sub_lis)
        for var in sub_lis:
            if not var in benc and not var in lis:
                lis.append(var)
    return lis


if __name__ == "__main__":

    # Wat11

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2 = symbols(
        "alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2"
    )

    k1 = alpha + r * b
    k2 = r * b0
    k3 = r
    c1 = s * b - s1 * b + sp * b1
    c2 = s
    c3 = sp
    c4 = s1 * b + sp * b2
    c5 = s1
    # c5 = sp2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = 1
    mpk5 = b2

    unknown = [alpha, b, b0, b1, b2, r, s, s1, sp]

    k = [k1, k2, k3]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk5]

    correct_form(k, c, mpk, unknown)

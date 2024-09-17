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

"""proof_verification.py: Methods utilized for the automatic
verification of proofs."""


def verify_proof(masterkey, special_s, kenc, cenc, benc, proofs):
    """
    Checks if the symbolic property holds.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        proofs (list): List of proofs elements.

    Returns:
        (bool): Verification result.
        (str): Process log.
    """

    process_log = []

    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = (
        proofs
    )

    k_nonlone = []
    for k, _ in rvectors_nonlone:
        k_nonlone.append(k)
    c_nonlone = []
    for c, _ in svectors_nonlone:
        c_nonlone.append(c)
    substitutions = (
        rvectors_nonlone + rvectors_lone + benc_mats + svectors_nonlone + svectors_lone
    )

    masterkey_given = False
    masterkey_vec = rvectors_lone[0][1]  # .transpose()
    for k, vec in rvectors_lone:
        if k == masterkey:
            masterkey_vec = vec  # .transpose()
            masterkey_given = True
    special_s_given = False
    special_s_vec = svectors_nonlone[0][1]
    for c, vec in svectors_nonlone:
        if c == special_s:
            special_s_vec = vec
            special_s_given = True

    verifies_correctly = True

    if (
        special_s_vec * masterkey_vec == Matrix([[0]])
        or not masterkey_given
        or not special_s_given
    ):
        verifies_correctly = False
        # print("\n The proof does not verify correctly, because masterkey * special_s = " + str(masterkey) + " * " + str(special_s) + " = 0. \n")
        process_log.append(
            "\n The proof does not verify correctly, because masterkey * special_s = "
            + str(masterkey)
            + " * "
            + str(special_s)
            + " = 0. \n"
        )

    for k in kenc:
        if len(k.args) > 1:
            if is_poly(k, benc, rvectors_lone):
                evaluated = cancel(eval_poly(True, k, substitutions, benc))
                all_zero = zeros(shape(evaluated)[0], shape(evaluated)[1])
                if evaluated != all_zero:
                    # print("\n The proof does not verify correctly, because ", k, "!= 0 \n")
                    process_log.append(
                        "\n The proof does not verify correctly, because "
                        + str(k)
                        + " != 0 \n"
                    )
                    verifies_correctly = False

    for c in cenc:
        if len(c.args) > 1:
            if is_poly(c, benc, svectors_lone):
                evaluated = cancel(eval_poly(False, c, substitutions, benc))
                all_zero = zeros(shape(evaluated)[0], shape(evaluated)[1])
                if evaluated != all_zero:
                    # print("\n The proof does not verify correctly, because ", c, "!= 0 \n")
                    process_log.append(
                        "\n The proof does not verify correctly, because "
                        + str(c)
                        + " != 0 \n"
                    )
                    verifies_correctly = False

    # if verifies_correctly:
    #     print("\n The following symbolic property proof verifies correctly. \n")
    return verifies_correctly, "\n".join(process_log)


def verify_proof_ven23(masterkey, special_s, kenc, cenc, benc, proofs):
    """
    Checks if the symbolic property holds.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        proofs (list): List of proofs elements.

    Returns:
        (bool): Verification result.
        (str): Process log.
    """

    process_log = []

    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = (
        proofs
    )

    k_nonlone = []
    for k, _ in rvectors_nonlone:
        k_nonlone.append(k)
    c_nonlone = []
    for c, _ in svectors_nonlone:
        c_nonlone.append(c)
    substitutions = (
        rvectors_nonlone + rvectors_lone + benc_mats + svectors_nonlone + svectors_lone
    )

    """
    TODO
    masterkey_given = False
    masterkey_vec = rvectors_lone[0][1] #.transpose()
    for (k, vec) in rvectors_lone:
        if k == masterkey:
            masterkey_vec = vec #.transpose()
            masterkey_given = True
    special_s_given = False
    special_s_vec = svectors_nonlone[0][1]
    for (c, vec) in svectors_nonlone:
        if c == special_s:
            special_s_vec = vec
            special_s_given = True
    """

    verifies_correctly = True

    # TODO
    # if special_s_vec * masterkey_vec == Matrix([[0]]) or not masterkey_given or not special_s_given:
    #    verifies_correctly = False
    #    #print("\n The proof does not verify correctly, because masterkey * special_s = " + str(masterkey) + " * " + str(special_s) + " = 0. \n")
    #    process_log.append("\n The proof does not verify correctly, because masterkey * special_s = " + str(masterkey) + " * " + str(special_s) + " = 0. \n")

    # TODO
    """
    for k in kenc:
        if len(k.args) > 1:
            if is_poly(k, benc, rvectors_lone):
                evaluated = cancel(eval_poly(True, k, substitutions, benc))
                all_zero = zeros(shape(evaluated)[0], shape(evaluated)[1])
                if evaluated != all_zero:
                    #print("\n The proof does not verify correctly, because ", k, "!= 0 \n")
                    process_log.append("\n The proof does not verify correctly, because " + str(k) + " != 0 \n")
                    verifies_correctly = False
    """

    for c in cenc:
        if len(c.args) > 1:
            if is_poly(c, benc, svectors_lone):
                evaluated = cancel(eval_poly(False, c, substitutions, benc))
                all_zero = zeros(shape(evaluated)[0], shape(evaluated)[1])
                if evaluated != all_zero:
                    # print("\n The proof does not verify correctly, because ", c, "!= 0 \n")
                    process_log.append(
                        "\n The proof does not verify correctly, because "
                        + str(c)
                        + " != 0 \n"
                    )
                    verifies_correctly = False

    # if verifies_correctly:
    #     print("\n The following symbolic property proof verifies correctly. \n")
    return verifies_correctly, "\n".join(process_log)


def is_poly(entry, benc, lones):
    """
    Helper function to determine whether the encoding is a polynomial.

    Parameters:
        entry (sp.core.list.Symbol): Entry to analyze.
        benc (list): Public key encodings.
        lones (list): List of lone encodings.

    Returns:
        (bool): Result.
    """
    lone_args = []
    for lone_var, _ in lones:
        lone_args.append(lone_var)

    is_polynomial = False
    if type(entry) != int:
        lis = []
        recovervars(entry, lis)
        for var in lis:
            if var in benc or var in lone_args:
                is_polynomial = True
    return is_polynomial


# TODO: still in beta
def enhanced_symbolic_property(masterkey, kenc, cenc, benc, proofs):
    """
    Checks if the additional requirements of the enhanced symbolic property hold.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        proofs (list): Proofs elements.

    Returns:
        (bool): Analysis result.
    """
    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = (
        proofs
    )
    k_nonlone = []
    for k, _ in rvectors_nonlone:
        k_nonlone.append(k)
    c_nonlone = []
    for c, _ in svectors_nonlone:
        c_nonlone.append(c)
    substitutions = (
        rvectors_nonlone + rvectors_lone + benc_mats + svectors_nonlone + svectors_lone
    )

    for k, vec in rvectors_lone:
        if k == masterkey:
            masterkey_vec = vec.transpose()

    enhanced_s_p = True

    # first check
    masterkey_correct_form = masterkey_vec[0] != 0
    for el in masterkey_vec[1:]:
        if el != 0:
            masterkey_correct_form = False
    if not masterkey_correct_form:
        print("\n The master key is not of the correct form.\n")

    enhanced_s_p = enhanced_s_p and masterkey_correct_form

    # second check TODO

    # third check TODO

    # fourth check
    nl_i_r = nonlones_independent(rvectors_nonlone)
    nl_i_s = nonlones_independent(svectors_nonlone)
    if not nl_i_r:
        print("\n The non-lone key variables are not linearly independent. \n")
    if not nl_i_s:
        print("\n The non-lone ciphertext variables are not linearly independent. \n")

    enhanced_s_p = enhanced_s_p and nl_i_r and nl_i_s

    if enhanced_s_p:
        return True
        # print("\n The pair encoding satisfies the enhanced symbolic property. \n")


def nonlones_independent(list_of_nonlones):
    """
    Checks if the non-lone variables are linearly independent or not.

    Parameters:
        list_of_nonlones (list): List of non-lone variables.

    Returns:
        (bool): Result.
    """
    nonlone_vects = []
    for _, vec in list_of_nonlones:
        if shape(vec)[0] > 1:
            vec = vec.transpose()
        nonlone_vects.append(vec)
    mat = Matrix(nonlone_vects)
    rs = mat.rowspace()
    if shape(mat)[0] == len(rs):
        return True
    else:
        return False


def reorder_mono_args(mono_args, sub_args, benc, is_key_encoding):
    """
    Helper function to ensure that the product of vector and matrix is done in
    the right order.

    Parameters:
        mono_args (list): List of monomials.
        sub_args (list): Substituded values.
        benc (list): Public key encodings.
        is_key_encoding (bool): If it is a key encoding.
    Returns:
        (list): Ordered product of vector and matrix.
    """
    first_sub = 0
    second_sub = 0
    ctr = 0
    ctr_i = 0
    for arg in mono_args:
        if arg in sub_args:
            if ctr == 0:
                first_sub = (ctr_i, arg)
                ctr += 1
            else:
                second_sub = (ctr_i, arg)
        ctr_i += 1

    if is_key_encoding:
        if second_sub in benc:
            mono_args[first_sub[0]] = second_sub[1]
            mono_args[second_sub[0]] = first_sub[1]
    else:
        if first_sub[1] in benc:
            mono_args[first_sub[0]] = second_sub[1]
            mono_args[second_sub[0]] = first_sub[1]
    return mono_args


def eval_poly(is_key_encoding, poly, substitutions, benc):
    """
    Evaluates the given encoding polynomial with the substituted values.

    Parameters:
        is_key_encoding (bool): If it is a key encoding.
        poly (list): Polynomial.
        substitutions (list): Substituded values.
        benc (list): List of public key encodings.
    Returns:
        (list): Polynomial evaluation.
    """
    sub_args = []
    for arg, _ in substitutions:
        sub_args.append(arg)

    if poly.func == Mul:
        lis_var = []
        mono_args = list(poly.args)
        mono_args = reorder_mono_args(mono_args, sub_args, benc, is_key_encoding)
        for var in mono_args:
            if var in sub_args:
                ind = sub_args.index(var)
                lis_var.append(substitutions[ind][1])
            else:
                lis_var.append(var)
        subs_mono = prod(lis_var)  # .transpose()
        return subs_mono
    else:
        new_poly = []
        for mono in poly.args:
            if mono.func == Mul:
                lis_var = []
                mono_args = list(mono.args)
                mono_args = reorder_mono_args(
                    mono_args, sub_args, benc, is_key_encoding
                )
                for var in mono_args:
                    if var in sub_args:
                        ind = sub_args.index(var)
                        lis_var.append(substitutions[ind][1])
                    else:
                        lis_var.append(var)
                subs_mono = prod(lis_var)  # .transpose()
            else:
                if mono in sub_args:
                    ind = sub_args.index(mono)
                    subs_mono = substitutions[ind][1]
                else:
                    subs_mono = mono
            new_poly.append(subs_mono)
        sum_poly = new_poly[0]
        for mono in new_poly[1:]:
            sum_poly = sum_poly + mono
        return sum_poly


def verify_collusion_security_only(masterkey, special_s, kenc, cenc, benc, proofs):
    """
    Verifies the security against collusion by inspecting the security proofs
    generated by the proving functionality - the vectors for the master key
    and special_s should be (1,0,...,0).

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        proofs (list): Proof elements.
    Returns:
        (bool): Verification result.
        (str): Process log.
    """
    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = (
        proofs
    )
    result, process_log = verify_proof(masterkey, special_s, kenc, cenc, benc, proofs)
    if result:
        # first check
        for k, vec in rvectors_lone:
            if k == masterkey:
                masterkey_vec = vec  # .transpose()
        masterkey_correct_form = masterkey_vec[0] != 0
        for el in masterkey_vec[1:]:
            if el != 0:
                masterkey_correct_form = False
        if not masterkey_correct_form:
            result = False
        # second check
        for c, vec in svectors_nonlone:
            if c == special_s:
                s_vec = vec  # .transpose()
        s_correct_form = s_vec[0] != 0
        for el in s_vec[1:]:
            if el != 0:
                s_correct_form = False
        if not s_correct_form:
            result = False
    return result, process_log

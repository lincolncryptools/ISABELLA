#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023
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

# This module contains the required methods to implement the Ven23
# compiler, proposed in https://eprint.iacr.org/2023/143.pdf

import copy
from sympy import symbols
from acabella.core.common.utils import *

## Functions for finding variables or group of variables in
## monomials that are part of GPES polynomial encodings. They
## assume the encodings pass the validate_ functions defined below.


def capture_alphas_from_cm(cm: list, alphas: list):

    # NOTE: Assumes the format of the CM encoding is GPES.
    # You can use the format validation functions for CM
    # before running this function.

    captured_alphas = []
    cm_monos = []

    try:
        for elem in cm:
            recovermonos(elem, cm_monos)
            cm_monos = list(filter(lambda item: item is not None, cm_monos))

            if not cm_monos:
                return False, "CM encoding is malformed or incorrect, leaving..."

            for i in range(len(cm_monos)):

                if cm_monos[i].func == Mul and (
                    len(cm_monos[i].args) == 2 or len(cm_monos[i].args) == 3
                ):
                    inter = list(set(cm_monos[i].args) & set(alphas))
                    if inter:
                        captured_alphas.append(inter[0])
    except AttributeError:
        return False, "CM encoding is malformed or incorrect, leaving..."

    return captured_alphas


def is_integer_or_known_variable(elem, known_vars: list) -> bool:
    """
    This functions checks if elem is an integer
    or a known variable.

    Parameters:
        elem (Symbols): symbol
        known_vars (list): List of known variables.

    Returns:
        (bool): Validation result.
    """

    A11, A12, A21, A22 = symbols("A11, A12, A21, A22")

    if (
        type(elem) == int
        or type(elem) == Integer
        or elem in known_vars
        or elem in [A11, A12, A21, A22]
    ):
        return True
    else:
        return False


def is_var_common_or_alpha(var, common, alphas):
    return var in common or var in alphas


def is_var_non_lone_in_monomial(
    var, monomial, non_lone_vars, common_vars, alphas, known_vars
):

    if len(monomial.args) == 0:
        return False

    if len(monomial.args) == 2:
        if monomial.func != Mul:
            return False

        if var in monomial.args:
            if var in non_lone_vars:
                if is_var_common_or_alpha(
                    monomial.args[0], common_vars, alphas
                ) or is_var_common_or_alpha(monomial.args[1], common_vars, alphas):
                    return True

    if len(monomial.args) == 3:

        if monomial.func != Mul:
            return False

        if var in monomial.args:
            if var in non_lone_vars:
                if (
                    is_var_common_or_alpha(monomial.args[0], common_vars, alphas)
                    or is_var_common_or_alpha(monomial.args[1], common_vars, alphas)
                    or is_var_common_or_alpha(monomial.args[2], common_vars, alphas)
                ):
                    if (
                        is_integer_or_known_variable(monomial.args[0], known_vars)
                        or is_integer_or_known_variable(monomial.args[1], known_vars)
                        or is_integer_or_known_variable(monomial.args[2], known_vars)
                    ):
                        return True

    return False


def is_var_lone_in_monomial(var, monomial, lone_vars, known_vars):

    if len(monomial.args) == 0:
        if var in lone_vars:
            return True

    if len(monomial.args) == 2:
        if monomial.func != Mul:
            return False

        if var in monomial.args:
            if var in lone_vars:
                if is_integer_or_known_variable(
                    monomial.args[0], known_vars
                ) or is_integer_or_known_variable(monomial.args[1], known_vars):
                    return True

    return False


def validate_vars_in_cm_encoding(
    captured_alphas: list,
    captured_lone_vars: list,
    captured_non_lone_vars: list,
    cenc: list,
    lone_vars,
    non_lone_vars,
    common_vars,
    alphas,
    known_vars,
    kenc: list,
):
    """
    Ensures that all the supplied lone variables and non-lone variables (from CM, normally) appear
    as lone and non-lone variables, respectively, in the cenc encodings.

    Finally, this function checks if the non-lone variables in CM (alphas) occur as singleton in the key
    encoding.

    NOTE: It doesn't validate that the supplied ciphertext encodings
    are well formatted. For that, you should use the validation functions
    implemented below.

    Parameters:
        captured_alphas (list): List of alphas in CM.
        captured_lone_vars (list): List of lone variables in CM.
        captured_non_lone_vars (list): List of non-lone variables in CM.
        cenc (list): List of Symbol.

    Returns:
        (bool): Validation result
    """

    working_lone_vars = copy.deepcopy(captured_lone_vars)
    working_non_lone_vars = copy.deepcopy(captured_non_lone_vars)
    working_alpha_vars = copy.deepcopy(captured_alphas)

    for ct_encoding in cenc:

        print("Processing encoding: : ", ct_encoding)

        ct_encoding_monos = []

        try:
            recovermonos(ct_encoding, ct_encoding_monos)
            ct_encoding_monos = list(
                filter(lambda item: item is not None, ct_encoding_monos)
            )

            print("\tMonomials for this encoding: ", ct_encoding_monos)

            if not ct_encoding_monos:
                return False, "CT encoding is malformed or incorrect, leaving..."

            for i in range(len(ct_encoding_monos)):

                print("\t\tAnalyzing: ", ct_encoding_monos[i])

                # 1. Check if CM non-lone vars are in the encodings as non-lone vars

                inter = list(
                    set(working_non_lone_vars) & set(ct_encoding_monos[i].args)
                )

                if len(inter) > 1:
                    return False, "CT encoding is malformed or incorrect: " + str(
                        inter
                    ) + " in " + str(ct_encoding_monos[i].args)

                if len(inter) == 1:

                    # it appears in the monomial, but is acting as a non-lone var ?

                    if is_var_non_lone_in_monomial(
                        inter[0],
                        ct_encoding_monos[i],
                        non_lone_vars,
                        common_vars,
                        alphas,
                        known_vars,
                    ):
                        if inter[0] in working_non_lone_vars:
                            working_non_lone_vars.remove(inter[0])

                # 2. Check if CM lone vars are in the encodings as lone vars

                inter = list(set(working_lone_vars) & set(ct_encoding_monos[i].args))

                if len(inter) > 1:
                    return False, "CT encoding is malformed or incorrect: " + str(
                        inter
                    ) + " in " + str(ct_encoding_monos[i].args)

                if len(inter) == 1:

                    # it appears in the monomial, but is acting as a non-lone var ?

                    if is_var_lone_in_monomial(
                        inter[0], ct_encoding_monos[i], lone_vars, known_vars
                    ):
                        if inter[0] in working_lone_vars:
                            working_lone_vars.remove(inter[0])

        except AttributeError:
            return False, "CT encoding is malformed or incorrect, leaving..."

    # 3. Check if non-lone variables in CM (alphas) occur as singleton in the key
    # encoding

    for k_encoding in kenc:

        print("Processing encoding: : ", k_encoding)

        k_encoding_monos = []

        try:
            recovermonos(k_encoding, k_encoding_monos)
            k_encoding_monos = list(
                filter(lambda item: item is not None, k_encoding_monos)
            )

            print("\tMonomials for this encoding: ", k_encoding_monos)

            if not k_encoding_monos:
                return False, "k encoding is malformed or incorrect, leaving..."

            for i in range(len(k_encoding_monos)):

                print("\t\tAnalyzing: ", k_encoding_monos[i])

                # Check if alphas are in the encodings as lone vars

                inter = list(set(working_alpha_vars) & set(k_encoding_monos[i].args))

                # another attempt in case there is a single element in the monomial

                if inter == []:
                    inter = list(set(working_alpha_vars) & set([k_encoding_monos[i]]))

                if len(inter) > 1:
                    return False, "k encoding is malformed or incorrect: " + str(
                        inter
                    ) + " in " + str(k_encoding_monos[i].args)

                if len(inter) == 1:

                    # it appears in the monomial, but is acting as a non-lone var ?

                    if is_var_lone_in_monomial(
                        inter[0], k_encoding_monos[i], alphas, known_vars
                    ):
                        if inter[0] in working_alpha_vars:
                            working_alpha_vars.remove(inter[0])

        except AttributeError:
            return False, "k encoding is malformed or incorrect, leaving..."

    if not working_lone_vars and not working_non_lone_vars and not working_alpha_vars:
        return True, None
    else:
        msg = ""

        if not working_lone_vars:
            msg = (
                msg
                + " CM lone-vars don't appear as lone-vars in the ciphertext encoding"
            )
        if not working_non_lone_vars:
            msg = (
                msg
                + " CM non-lone-vars don't appear as non-lone-vars in the ciphertext encoding"
            )
        if not working_alpha_vars:
            msg = msg + " CM alphas don't appear as singletons in the key encodings"

        return False, "Not all CM elements appear in the ciphertext encodings " + msg


def capture_vars_from_cm(
    cm: list, lone_vars: list, non_lone_vars: list, alphas: list, known_vars: list
):
    """
    Given a list of lone and non-lone vars, it finds all the ocurrences
    in the encoding list.

    NOTE: It doesn't guarantee that the CM encoding is fully GPES, this
    should be verified using the validate functions defined in this module.

    NOTE: This function is deprecated. Use instead the capture_lone_vars_from_encoding
    and its counterpart functions.

    Parameters:
        encoding (list): List of Symbol.
        lone_vars (list): List of lone variables.
        non_lone_vars (list): List of non-lone variables.
        alphas (list): List of mpk alpha encodings.
        known_vars (list): List of known variables.

    Returns:
        (list, list): List of found lone variables, list of found non-lone variables
    """

    cm_monos = []
    captured_lone_vars = []
    captured_non_lone_vars = []

    try:
        recovermonos(cm, cm_monos)
        cm_monos = list(filter(lambda item: item is not None, cm_monos))

        if not cm_monos:
            return False, "CM encoding is malformed or incorrect, leaving..."

        for i in range(len(cm_monos)):

            # is a lone var ?
            if cm_monos[i] in lone_vars:
                captured_lone_vars.append(cm_monos[i])
            else:
                # or lone var * int ?
                if cm_monos[i].func == Mul and len(cm_monos[i].args) == 2:
                    if is_integer_or_known_variable(
                        cm_monos[i].args[0], known_vars
                    ) or is_integer_or_known_variable(cm_monos[i].args[1], known_vars):
                        if (cm_monos[i].args[0]) in lone_vars:
                            captured_lone_vars.append(cm_monos[i].args[0])
                        if (cm_monos[i].args[1]) in lone_vars:
                            captured_lone_vars.append(cm_monos[i].args[1])

                # or non-lone and alpha_j's ?
                if cm_monos[i].func == Mul and len(cm_monos[i].args) == 2:
                    if (cm_monos[i].args[0]) in alphas or (
                        cm_monos[i].args[1]
                    ) in alphas:
                        if cm_monos[i].args[0] in non_lone_vars:
                            captured_non_lone_vars.append(cm_monos[i].args[0])
                        if cm_monos[i].args[1] in non_lone_vars:
                            captured_non_lone_vars.append(cm_monos[i].args[1])

    except AttributeError:
        return False, "CM encoding is malformed or incorrect, leaving..."

    return captured_lone_vars, captured_non_lone_vars


# The following functions validate the format of the (input) polynomial encodings
# according to the GPES definition in https://eprint.iacr.org/2023/143.pdf


def validate_cm_element_a(elem, lone_vars: list, known_vars: list) -> bool:
    """
    This functions validates the first elem of the CM encoding:
        - is 1 or two elements in multiplication
        - 1 element: must be a lone variable
        - 2 elements: must be lone variable and one integer

    Parameters:
        elem (Symbols): CM encoding.
        lone_vars (list): List of lone variables.
        known_vars (list): List of known variables.

    Returns:
        (bool): Validation result.
    """

    try:

        if len(elem.args) == 0:
            if elem in lone_vars:
                return True
            else:
                return False

        if len(elem.args) == 2:

            if elem.func != Mul:
                return False

            if is_integer_or_known_variable(
                elem.args[0], known_vars
            ) or is_integer_or_known_variable(elem.args[1], known_vars):
                if (elem.args[0]) in lone_vars or (elem.args[1]) in lone_vars:
                    return True
                else:
                    return False

        return False

    except AttributeError:
        return False


def validate_cm_element_b(
    elem, non_lone_vars: list, alphas: list, known_vars: list
) -> bool:
    """
    This functions validates the first elem of the CM encoding:
        - consists of 2 or 3 elements in multiplication
        - 2 element: 1 alpha, 1 non-lone
        - 3 elements: 1 integer, 1 alpha, 1 non-lone

    Parameters:
        elem (Symbols): CM encoding.
        non_lone_vars (list): List of non-lone variables.
        alphas (list): List of alphas.

    Returns:
        (bool): Validation result.
    """

    try:
        if len(elem.args) == 2:

            if elem.func != Mul:
                return False

            if (elem.args[0]) in non_lone_vars or (elem.args[1]) in non_lone_vars:
                if (elem.args[0]) in alphas or (elem.args[1]) in alphas:
                    return True
                else:
                    return False

        if len(elem.args) == 3:

            if elem.func != Mul:
                return False

            if (
                (elem.args[0]) in non_lone_vars
                or (elem.args[1]) in non_lone_vars
                or (elem.args[2]) in non_lone_vars
            ):
                if (
                    (elem.args[0]) in alphas
                    or (elem.args[1]) in alphas
                    or (elem.args[2]) in alphas
                ):
                    if (
                        is_integer_or_known_variable(elem.args[0], known_vars)
                        or is_integer_or_known_variable(elem.args[1], known_vars)
                        or is_integer_or_known_variable(elem.args[2], known_vars)
                    ):
                        return True
                    else:
                        return False

        return False

    except AttributeError:
        return False


def validate_cp_element_a(elem, lone_vars: list, known_vars: list) -> bool:
    return validate_cm_element_a(elem, lone_vars, known_vars)


def validate_cp_element_b(
    elem, non_lone_vars: list, alphas: list, known_vars: list
) -> bool:
    return validate_cm_element_b(elem, non_lone_vars, alphas, known_vars)


def validate_c_element_a(elem, lone_vars: list, known_vars: list) -> bool:
    return validate_cm_element_a(elem, lone_vars, known_vars)


def validate_c_element_b(
    elem, non_lone_vars: list, common: list, known_vars: list
) -> bool:
    """
    This functions validates the first elem of the c encoding:
        - consists of 2 or 3 elements in multiplication
        - 2 element: 1 non-lone, 1 common
        - 3 elements: 1 integer, 1 non-lone, 1 common

    Parameters:
        elem (Symbols): c encoding.
        non_lone_vars (list): List of non-lone variables.
        common (list): List of alphas.
        known_vars (list): List of known variables.

    Returns:
        (bool): Validation result.
    """

    try:
        if len(elem.args) == 2:

            if elem.func != Mul:
                return False

            if (elem.args[0]) in non_lone_vars or (elem.args[1]) in non_lone_vars:
                if (elem.args[0]) in common or (elem.args[1]) in common:
                    return True
                else:
                    return False

        if len(elem.args) == 3:

            if elem.func != Mul:
                return False

            if (
                (elem.args[0]) in non_lone_vars
                or (elem.args[1]) in non_lone_vars
                or (elem.args[2]) in non_lone_vars
            ):
                if (
                    (elem.args[0]) in common
                    or (elem.args[1]) in common
                    or (elem.args[2]) in common
                ):
                    if (
                        is_integer_or_known_variable(elem.args[0], known_vars)
                        or is_integer_or_known_variable(elem.args[1], known_vars)
                        or is_integer_or_known_variable(elem.args[2], known_vars)
                    ):
                        return True
                    else:
                        return False

        return False

    except AttributeError:
        return False


def validate_k_element_a(elem, alphas: list, known_vars: list) -> bool:
    """
    This functions validates the first elem of the k encoding:
        - is 1 or two elements in multiplication
        - 1 element: must be an alpha
        - 2 elements: must be alpha and one integer

    Parameters:
        elem (Symbols): k encoding.
        alphas (list): List of alphas variables.
        known_vars (list): List of known variables.

    Returns:
        (bool): Validation result.
    """

    try:

        if len(elem.args) == 0:
            if elem in alphas:
                return True
            else:
                return False

        if len(elem.args) == 2:

            if elem.func != Mul:
                return False

            if is_integer_or_known_variable(
                elem.args[0], known_vars
            ) or is_integer_or_known_variable(elem.args[1], known_vars):
                if (elem.args[0]) in alphas or (elem.args[1]) in alphas:
                    return True
                else:
                    return False

        return False

    except AttributeError:
        return False


def validate_k_element_b(elem, lone_vars: list, known_vars: list) -> bool:
    """
    This functions validates the first elem of the k encoding:
        - is 1 or two elements in multiplication
        - 1 element: must be a lone r_hat
        - 2 elements: must be lone r_hat and one integer

    Parameters:
        elem (Symbols): k encoding.
        lone_vars (list): List of alphas variables.
        known_vars (list): List of known variables.

    Returns:
        (bool): Validation result.
    """

    try:

        if len(elem.args) == 0:
            if elem in lone_vars:
                return True
            else:
                return False

        if len(elem.args) == 2:

            if elem.func != Mul:
                return False

            if is_integer_or_known_variable(
                elem.args[0], known_vars
            ) or is_integer_or_known_variable(elem.args[1], known_vars):
                if (elem.args[0]) in lone_vars or (elem.args[1]) in lone_vars:
                    return True
                else:
                    return False

        return False

    except AttributeError:
        return False


def validate_k_element_c(
    elem, non_lone_vars: list, common: list, known_vars: list
) -> bool:
    return validate_c_element_b(elem, non_lone_vars, common, known_vars)


def validate_k_encoding_format(
    kenc: list,
    alphas: list,
    known_vars: list,
    lone_vars: list,
    non_lone_vars: list,
    common: list,
) -> bool:

    k_monos = []

    try:
        for elem in kenc:
            recovermonos(elem, k_monos)
            k_monos = list(filter(lambda item: item is not None, k_monos))

            if not k_monos:
                return False, "key encoding is malformed or incorrect, leaving..."

            for i in range(len(k_monos)):
                r_a = validate_k_element_a(k_monos[i], alphas, known_vars)
                r_b = validate_k_element_b(k_monos[i], lone_vars, known_vars)
                r_c = validate_k_element_c(
                    k_monos[i], non_lone_vars, common, known_vars
                )

                mono_is_valid = r_a or r_b or r_c

                if not mono_is_valid:
                    return False

    except AttributeError:
        return False, "key encoding is malformed or incorrect, leaving..."

    return True


def validate_c_encoding_format(
    cenc: list, lone_vars: list, known_vars: list, non_lone_vars: list, common: list
) -> bool:

    c_monos = []

    try:
        for elem in cenc:
            recovermonos(elem, c_monos)
            c_monos = list(filter(lambda item: item is not None, c_monos))

            if not c_monos:
                return (
                    False,
                    "ciphertext encoding is malformed or incorrect, leaving...",
                )

            for i in range(len(c_monos)):
                r_a = validate_c_element_a(c_monos[i], lone_vars, known_vars)
                r_b = validate_c_element_b(
                    c_monos[i], non_lone_vars, common, known_vars
                )

                mono_is_valid = r_a or r_b

                if not mono_is_valid:
                    return False

    except AttributeError:
        return False, "ciphertext encoding is malformed or incorrect, leaving..."

    return True


def validate_cp_encoding_format(
    cpenc: list, lone_vars: list, known_vars: list, non_lone_vars: list, alphas: list
) -> bool:

    c_monos = []

    try:
        for elem in cpenc:
            recovermonos(elem, c_monos)
            c_monos = list(filter(lambda item: item is not None, c_monos))

            if not c_monos:
                return (
                    False,
                    "ciphertext encoding is malformed or incorrect, leaving...",
                )

            for i in range(len(c_monos)):
                r_a = validate_cp_element_a(c_monos[i], lone_vars, known_vars)
                r_b = validate_cp_element_b(
                    c_monos[i], non_lone_vars, alphas, known_vars
                )

                mono_is_valid = r_a or r_b

                if not mono_is_valid:
                    return False

    except AttributeError:
        return False, "ciphertext encoding is malformed or incorrect, leaving..."

    return True


def validate_cm_encoding_format(
    cmenc: list, lone_vars: list, known_vars: list, non_lone_vars: list, alphas: list
) -> bool:

    # lone_vars and non_lone_vars are related to those variables in the ciphertext encoding

    c_monos = []

    try:
        for elem in cmenc:
            recovermonos(elem, c_monos)
            c_monos = list(filter(lambda item: item is not None, c_monos))

            if not c_monos:
                return False, "CM encoding is malformed or incorrect, leaving..."

            for i in range(len(c_monos)):
                r_a = validate_cm_element_a(c_monos[i], lone_vars, known_vars)
                r_b = validate_cm_element_b(
                    c_monos[i], non_lone_vars, alphas, known_vars
                )

                mono_is_valid = r_a or r_b

                if not mono_is_valid:
                    return False

    except AttributeError:
        return False, "CM encoding is malformed or incorrect, leaving..."

    return True


# Variable capture functions


def capture_lone_vars_from_encoding(
    encodings: list, known_vars: list, alphas: list, common_vars: list
):

    lone_vars = []

    for encoding in encodings:

        print("Processing encoding: : ", encoding)

        encoding_monos = []

        try:
            recovermonos(encoding, encoding_monos)
            encoding_monos = list(filter(lambda item: item is not None, encoding_monos))

            print("\tMonomials for this encoding: ", encoding_monos)

            if not encoding_monos:
                pass

            for i in range(len(encoding_monos)):

                print("\t\tAnalyzing: ", encoding_monos[i])

                if len(encoding_monos[i].args) == 0:

                    if not is_var_common_or_alpha(
                        encoding_monos[i], common_vars, alphas
                    ):
                        if not is_integer_or_known_variable(
                            encoding_monos[i], known_vars
                        ):
                            print("ADD: ", encoding_monos[i])
                            lone_vars.append(encoding_monos[i])

                if len(encoding_monos[i].args) == 2:
                    if encoding_monos[i].func == Mul:
                        if is_integer_or_known_variable(
                            encoding_monos[i].args[0], known_vars
                        ):
                            if not is_var_common_or_alpha(
                                encoding_monos[i].args[1], common_vars, alphas
                            ):
                                if not is_integer_or_known_variable(
                                    encoding_monos[i].args[1], known_vars
                                ):
                                    lone_vars.append(encoding_monos[i].args[1])

                        if is_integer_or_known_variable(
                            encoding_monos[i].args[1], known_vars
                        ):
                            if not is_var_common_or_alpha(
                                encoding_monos[i].args[0], common_vars, alphas
                            ):
                                if not is_integer_or_known_variable(
                                    encoding_monos[i].args[0], known_vars
                                ):
                                    lone_vars.append(encoding_monos[i].args[0])

        except:
            pass

    # remove duplicates

    return list(dict.fromkeys(lone_vars))


def capture_non_lone_vars_from_encoding(
    encodings: list, known_vars: list, alphas: list, common_vars: list
):

    non_lone_vars = []

    for encoding in encodings:

        print("Processing encoding: : ", encoding)

        encoding_monos = []

        try:
            recovermonos(encoding, encoding_monos)
            encoding_monos = list(filter(lambda item: item is not None, encoding_monos))

            print("\tMonomials for this encoding: ", encoding_monos)

            if not encoding_monos:
                pass

            for i in range(len(encoding_monos)):

                print("\t\tAnalyzing: ", encoding_monos[i])

                if len(encoding_monos[i].args) == 2:
                    if encoding_monos[i].func == Mul:
                        if is_var_common_or_alpha(
                            encoding_monos[i].args[0], common_vars, alphas
                        ):
                            non_lone_vars.append(encoding_monos[i].args[1])

                        if is_var_common_or_alpha(
                            encoding_monos[i].args[1], common_vars, alphas
                        ):
                            non_lone_vars.append(encoding_monos[i].args[0])

                if len(encoding_monos[i].args) == 3:
                    if encoding_monos[i].func == Mul:
                        if is_integer_or_known_variable(
                            encoding_monos[i].args[0], known_vars
                        ):
                            if is_var_common_or_alpha(
                                encoding_monos[i].args[1], common_vars, alphas
                            ):
                                non_lone_vars.append(encoding_monos[i].args[2])
                            if is_var_common_or_alpha(
                                encoding_monos[i].args[2], common_vars, alphas
                            ):
                                non_lone_vars.append(encoding_monos[i].args[1])

                        if is_integer_or_known_variable(
                            encoding_monos[i].args[1], known_vars
                        ):
                            if is_var_common_or_alpha(
                                encoding_monos[i].args[0], common_vars, alphas
                            ):
                                non_lone_vars.append(encoding_monos[i].args[2])
                            if is_var_common_or_alpha(
                                encoding_monos[i].args[2], common_vars, alphas
                            ):
                                non_lone_vars.append(encoding_monos[i].args[0])

                        if is_integer_or_known_variable(
                            encoding_monos[i].args[2], known_vars
                        ):
                            if is_var_common_or_alpha(
                                encoding_monos[i].args[1], common_vars, alphas
                            ):
                                non_lone_vars.append(encoding_monos[i].args[0])
                            if is_var_common_or_alpha(
                                encoding_monos[i].args[0], common_vars, alphas
                            ):
                                non_lone_vars.append(encoding_monos[i].args[1])

        except:
            pass

    # remove duplicates
    return list(dict.fromkeys(non_lone_vars))


def validate_cm(
    c_encodings: list,
    cp_encodings: list,
    cm_encodings: list,
    k_encodings: list,
    alphas: list,
    common_vars: list,
    known_vars: list,
):
    """

    This functions determines if the given ABE scheme is a valid GPES scheme.

    Parameters:
        c_encodings (list): List of ciphertext encodings.
        cp_encodings (list): List of ciphertext prime encodings.
        cm_encoding (list): CM encoding.
        k_encodings (list): List of key encondings.
        alphas (list): List of alphas.
        common_vars (list): List of common variables (mpk).
        known_vars (list): List of known variables.

    Returns:
        (bool): Validation result.
        (msg): Cause of error.
    """

    # capture lone and non-lone vars from ciphertext and key encodings

    cm_alphas = []

    c_lone_vars = []
    cm_lone_vars = []
    cp_lone_vars = []
    k_lone_vars = []

    c_non_lone_vars = []
    cm_non_lone_vars = []
    cp_non_lone_vars = []
    k_non_lone_vars = []

    if c_encodings:
        c_lone_vars = capture_lone_vars_from_encoding(
            c_encodings, known_vars, alphas, common_vars
        )
        c_non_lone_vars = capture_non_lone_vars_from_encoding(
            c_encodings, known_vars, alphas, common_vars
        )
    else:
        return False, "No provided ciphertext encodings"

    if cm_encodings:
        cm_lone_vars = capture_lone_vars_from_encoding(
            cm_encodings, known_vars, alphas, common_vars
        )
        cm_non_lone_vars = capture_non_lone_vars_from_encoding(
            cm_encodings, known_vars, alphas, common_vars
        )
    else:
        return False, "No provided CM encodings"

    if cp_encodings:
        cp_lone_vars = capture_lone_vars_from_encoding(
            cp_encodings, known_vars, alphas, common_vars
        )
        cp_non_lone_vars = capture_non_lone_vars_from_encoding(
            cp_encodings, known_vars, alphas, common_vars
        )

    if k_encodings:
        k_lone_vars = capture_lone_vars_from_encoding(
            k_encodings, known_vars, alphas, common_vars
        )
        k_non_lone_vars = capture_non_lone_vars_from_encoding(
            k_encodings, known_vars, alphas, common_vars
        )
    else:
        return False, "No provided key encodings"

    cm_alphas = capture_alphas_from_cm(cm_encodings, alphas)

    # validate encoding format

    k_format_is_valid = False
    c_format_is_valid = False
    cp_format_is_valid = False
    cm_format_is_valid = False

    k_format_is_valid = validate_k_encoding_format(
        k_encodings, alphas, known_vars, k_lone_vars, k_non_lone_vars, common_vars
    )
    c_format_is_valid = validate_c_encoding_format(
        c_encodings, c_lone_vars, known_vars, c_non_lone_vars, common_vars
    )

    if cp_encodings:
        cp_format_is_valid = validate_cp_encoding_format(
            cp_encodings, cp_lone_vars, known_vars, cp_non_lone_vars, alphas
        )
    else:
        cp_format_is_valid = True

    cm_format_is_valid = validate_cm_encoding_format(
        cm_encodings,
        list(dict.fromkeys(c_lone_vars + cp_lone_vars)),
        known_vars,
        list(dict.fromkeys(c_non_lone_vars + cp_non_lone_vars)),
        alphas,
    )

    if not k_format_is_valid:
        return False, "Key encoding format is not valid according to GPES"

    if not c_format_is_valid:
        return False, "Ciphertext encoding format is not valid according to GPES"

    if not cp_format_is_valid:
        return False, "Cp encoding format is not valid according to GPES"

    if not cm_format_is_valid:
        return False, "CM encoding format is not valid according to GPES"

    # validate CM

    res, msg = validate_vars_in_cm_encoding(
        cm_alphas,
        cm_lone_vars,
        cm_non_lone_vars,
        c_encodings + cp_encodings,
        c_lone_vars + cp_lone_vars,
        c_non_lone_vars + cp_non_lone_vars,
        common_vars,
        alphas,
        known_vars,
        k_encodings,
    )

    return res, msg

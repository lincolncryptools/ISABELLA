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

"""access_structures.py: This module contains functions for generating specific
access structures and for generating encodings utilized in the ACABELLA
analysis methods."""

from acabella.core.common.utils import *
from sympy import *

init_printing(use_unicode=True)


# returns an indexed encoding with prefix, e.g., r_1
def get_indexed_encoding(prefix, index):
    """
    Returns an indexed encoding with prefix with extra indices for the
    attribute and the key nr, e.g., r_(1,att).

    Parameters:
        prefix (str): Prefix to add to the encoding.
        index (str): Index to add at the end of the encoding.

    Returns:
        (sp.core.list.Symbol): Indexed encoding
    """
    return parse_expr("indexed_enc_" + prefix + "_" + str(index))


def get_indexed_encoding_extra_index(prefix, index1, index2, index_key):
    """
    Returns an indexed encoding with prefix with extra indices (2) for the
    attribute and the key nr, e.g., r_(1,att).

    Parameters:
        prefix (str): Prefix to add to the encoding.
        index1 (str): First index to add.
        index2 (str): Second index to add.
        index_key (str): Index to add at the end of the encoding.

    Returns:
        (sp.core.list.Symbol): Indexed encoding
    """
    return parse_expr(
        prefix + "_(" + str(index1) + ",att_" + str(index2) + "," + str(index_key) + ")"
    )


def get_attribute_in_group(index):
    """
    Returns a public key b_att for attribute with index

    Parameters:
        index (str): Index to add at the end of the encoding.

    Returns:
        (sp.core.list.Symbol): Encoding starting with b_
    """
    return parse_expr("b_" + str(index))


def get_attribute_as_scalar(index):
    """
    Returns a scalar x_att for some index

    Parameters:
        index (str): Index to add at the end of the encoding.

    Returns:
        (sp.core.list.Symbol): Encoding starting with x_
    """
    return parse_expr("x_" + str(index))


def get_i_of_n_policy_shares(index, length, special_s):
    """
    Get the i-th share for a policy of length n for a policy
    consisting of an AND-gate.

    Parameters:
        index (int): Position in the lambda vector.
        length (int): Length of the AND policy matrix.
        special_s (sp.core.list.Symbol): Sympy description of s.

    Returns:
        (sp.core.list.Symbol): Value of lambda vector at index position.
    """
    vec_lambda = create_policy_matrix_for_AND(length) * create_share_vector(
        length, special_s
    )
    return vec_lambda[index]


def get_i_of_n_policy_shares_general(index, length, special_s):
    """
    Get the i-th share for a policy of length n where the policy is a general matrix.

    Parameters:
        index (int): Position in the lambda vector.
        length (int): Length of the AND policy matrix.
        special_s (sp.core.list.Symbol): Sympy description of s.

    Returns:
        (sp.core.list.Symbol): Value of lambda vector at index position.
    """
    vec_lambda = create_policy_matrix_for_general_access_policy(
        length
    ) * create_share_vector(length, special_s)
    return vec_lambda[index]


def create_share_vector(length, special_s):
    """
    Creates a share vector v.

    Parameters:
        length (int): Length of the policy matrix.
        special_s (sp.core.list.Symbol): Sympy description of s.

    Returns:
        (list): Vector of shares.
    """
    vec_v = zeros(length, 1)
    vec_v[0, 0] = special_s
    for ind in range(1, length):
        vec_v[ind, 0] = parse_expr("v_" + str(ind + 1))
    return vec_v


def create_policy_matrix_for_AND(length):
    """
    Creates a policy matrix for the AND-gate of a given length.

    Parameters:
        length (int): Length of the policy matrix.

    Returns:
        (array): Policy matrix for AND.
    """
    matrix_A = zeros(length, length)
    matrix_A[0, 0] = 1
    matrix_A[0, 1] = 1
    matrix_A[length - 1, length - 1] = -1
    for ind in range(1, length - 1):
        matrix_A[ind, ind] = -1
        matrix_A[ind, ind + 1] = 1
    return matrix_A


def create_policy_matrix_for_general_access_policy(length):
    """
    Creates a policy matrix for the  general case of a given length.

    Parameters:
        length (int): Length of the policy matrix.

    Returns:
        (array): Policy matrix for AND.
    """
    matrix_A = zeros(length, length)
    for i in range(length):
        sum_row = 0
        for j in range(1, length):
            new_entry = parse_expr("A_(" + str(i + 1) + "," + str(j + 1) + ")")
            matrix_A[i, j] = new_entry
            w_entry = parse_expr("w_" + str(j + 1))
            sum_row -= new_entry * w_entry
        # matrix_A[i,0] = parse_expr("A_(" + str(i+1) + ",1)")
        matrix_A[i, 0] = sum_row
    return matrix_A

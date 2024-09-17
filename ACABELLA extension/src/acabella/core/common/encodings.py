# -*- coding: utf-8 -*-

from acabella.core.common.utils import *
from sympy import *

from acabella.core.common.access_structures import *

init_printing(use_unicode=True)

"""encodings.py: This module contains functions for generating
general encodings utilized in the analysis methods of ACABELLA."""


def substitute_encodings(
    enc, special_s, index, att_range, prefixes, nr_indexed_encodings, key_nr
):
    att_mpk_group = parse_expr("att_mpk_group")
    att_scalar = parse_expr("att_scalar")
    policy_share = parse_expr("lambda_policy_share")

    substitutions = [
        (att_mpk_group, get_attribute_in_group(att_range[index])),
        (att_scalar, get_attribute_as_scalar(att_range[index])),
    ]

    if key_nr == 0:
        substitutions.append(
            (policy_share, get_i_of_n_policy_shares(index, len(att_range), special_s))
        )

    for pref in prefixes:
        for ix in range(nr_indexed_encodings):
            i_e = get_indexed_encoding(pref, ix + 1)
            i_e_2 = get_indexed_encoding_extra_index(
                pref, ix + 1, att_range[index], key_nr
            )
            substitutions.append((i_e, i_e_2))

    new_enc = []
    for entry in enc:
        new_enc.append(entry.subs(substitutions))
    return new_enc


def create_b_encoding(gp, mpk, att_range):
    """
    Creates the encoding for the common variables b based on the used attributes.

    Parameters:
        gp (list): List of global parameters.
        mpk (list): List of mpk encodings.

    Returns:
        (list): b encoding
    """
    benc = gp + mpk
    for ind in att_range:
        benc.append(get_attribute_in_group(ind))
    return benc


def create_key_encoding(
    k_fixed, k_att, att_range, prefixes, nr_indexed_encodings, key_index_range
):
    """
    This function creates key encodings for each entry in the key_index_range
    list, for attributes in the att_range.

    Parameters:
        k_fixed (list): List of fixed key encodings.
        k_att (list): List of attribute-dependent key encodings.
        nr_indexed_encodings (list): Indexed encodings.
        key_index_range (list): Key index range.

    Returns:
        (list): key encodings
    """
    kenc = k_fixed
    for ind2 in key_index_range:
        for ind in range(len(att_range)):
            no_s = parse_expr("no_s")
            kenc += substitute_encodings(
                k_att, no_s, ind, att_range, prefixes, nr_indexed_encodings, ind2
            )
    return kenc


def create_ciphertext_encoding(
    c_fixed, c_att, special_s, att_range, prefixes, nr_indexed_encodings
):
    """
    This function creates a ciphertext encoding for the attributes in the
    att_range, for the AND-policy over all the attributes

    Parameters:
        c_fixed (list): List of fixed ciphertext encodings.
        c_att (list): List of attribute-dependent ciphertext encodings.
        special_s (list): Description of s.
        att_range (list): Attributes to use in the ciphertext encoding generation.
        prefixes (list): Prefixes to se.
        nr_indexed_encodings (list): Indexed encodings.
    Returns:
        (list): List of generated ciphertext encodings.
    """
    cenc = c_fixed
    for ind in range(len(att_range)):
        cenc += substitute_encodings(
            c_att, special_s, ind, att_range, prefixes, nr_indexed_encodings, 0
        )
    return cenc


def generate_unknown_variable_set(kenc, cenc, benc, att_range_ct, att_range_key):
    """
    Returns all unknown variables by determining all the variables in the
    encodings. It filters out those that are generated by get_attribute_as_scalar.

    Parameters:
        kenc (list): List of key encodings.
        cenc (list): List of ciphertext encodings.
        benc (list): List of b encodings.
        att_range_ct (list): Attributes in ciphertext range.
        att_range_key (list): Attributes in key range.
    Returns:
        (list): List of generated unknown variables.
    """
    all_vars = EmptySet

    for enc in benc + cenc + kenc:
        all_vars = Union(all_vars, enc.free_symbols)

    knowns = EmptySet
    for ind in att_range_ct + att_range_key:
        knowns = Union(knowns, {get_attribute_as_scalar(ind)})

    unknown = []
    for el in all_vars:
        contains = False
        for elp in knowns:
            if el == elp:
                contains = True
        if not contains:
            unknown.append(el)

    return unknown


# first try at taking into account declared unknown variables
def generate_unknown_variable_set_new(
    known, kenc, cenc, benc, att_range_ct, att_range_key
):
    """
    Returns all unknown variables by determining all the variables in the
    encodings. It filters out those that are generated by get_attribute_as_scalar.

    Parameters:
        kenc (list): List of key encodings.
        cenc (list): List of ciphertext encodings.
        benc (list): List of b encodings.
        att_range_ct (list): Attributes in ciphertext range.
        att_range_key (list): Attributes in key range.
    Returns:
        (list): List of generated unknown variables.
    """
    all_vars = EmptySet

    for enc in benc + cenc + kenc:
        all_vars = Union(all_vars, enc.free_symbols)

    knowns = EmptySet
    for elem in known:
        knowns = Union(knowns, {elem})
    for ind in att_range_ct + att_range_key:
        knowns = Union(knowns, {get_attribute_as_scalar(ind)})

    unknown = []
    for el in all_vars:
        contains = False
        for elp in knowns:
            if str(el)[: len(str(elp))] == str(elp):
                contains = True
        if not contains:
            unknown.append(el)

    return unknown


# first try at taking into account declared unknown variables
def generate_known_variable_set(unknown, kenc, cenc, benc):
    """
    Returns all known variables by determining all the variables in the
    encodings. .

    Parameters:
        kenc (list): List of key encodings.
        cenc (list): List of ciphertext encodings.
        benc (list): List of b encodings.
    Returns:
        (list): List of generated known variables.
    """
    all_vars = EmptySet

    for enc in benc + cenc + kenc:
        all_vars = Union(all_vars, enc.free_symbols)

    all_vars = list(all_vars)

    knowns = []
    for var in all_vars:
        if not var in unknown:
            knowns.append(var)
    return knowns

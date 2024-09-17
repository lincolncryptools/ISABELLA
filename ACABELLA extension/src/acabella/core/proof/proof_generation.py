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

"""proof_generation.py: Methods utilized for the automatic
generation of proofs of ABE schemes."""


def generate_proof_co_selective(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    Generates an AC17 co-selective proof.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): Co-selective proof.
    """
    output = generate_proof_selective(masterkey, special_s, cenc, kenc, benc, unknown)
    (benc_mats, rvectors_nonlone, rvectors_lone, svectors_nonlone, svectors_lone) = (
        output
    )

    if benc_mats == None:
        return output

    benc_mats_new = []
    for bx, mat in benc_mats:
        mat_new = mat.transpose()
        benc_mats_new.append((bx, mat_new))

    rvectors_nonlone_new = []
    for k, vec in rvectors_nonlone:
        vec_new = vec.transpose()
        rvectors_nonlone_new.append((k, vec_new))

    rvectors_lone_new = []
    for k, vec in rvectors_lone:
        vec_new = vec.transpose()
        rvectors_lone_new.append((k, vec_new))

    svectors_nonlone_new = []
    for c, vec in svectors_nonlone:
        vec_new = vec.transpose()
        svectors_nonlone_new.append((c, vec_new))

    svectors_lone_new = []
    for c, vec in svectors_lone:
        vec_new = vec.transpose()
        svectors_lone_new.append((c, vec_new))

    output = (
        benc_mats_new,
        svectors_nonlone_new,
        svectors_lone_new,
        rvectors_nonlone_new,
        rvectors_lone_new,
    )
    return output


def generate_proof_selective(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    Generates an AC17 selective proof.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): Selective proof.
    """
    kenc = canonical(kenc)
    cenc = canonical(cenc)
    (matk, uvectork) = writeencodingasprod(kenc, unknown)
    (matc, uvectorc) = writeencodingasprod(cenc, unknown)

    Mat_k = Matrix(matk)
    Mat_c = Matrix(matc)

    nonlone_c = determine_non_lone_vars_in_uvector(cenc, benc, uvectorc)

    (sublist_nonlones_c, sublist_lones_c) = sublistslonenonlone(nonlone_c)

    sublist_nonlones_c = put_special_s_first_entry(special_s, sublist_nonlones_c)

    # this can also be run with extend_mat_and_vec but yields larger vectors and matrices
    (Mat_c, uvectorc) = extend_mat_and_vec2(Mat_c, uvectorc, benc, sublist_nonlones_c)

    kern_c = Mat_c.nullspace()

    if len(kern_c) == 0:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    (benc_mats, _) = construct_benc_mats(benc, sublist_nonlones_c, uvectorc, kern_c)

    nonlone_k = determine_non_lone_vars_in_uvector(kenc, benc, uvectork)

    (sublist_nonlones_k, sublist_lones_k) = sublistslonenonlone(nonlone_k)

    bm_sh = shape(benc_mats[0][1])
    bm_rows = bm_sh[0]
    bm_columns = bm_sh[1]

    svectors_nonlone = []
    count = 0
    for c in sublist_nonlones_c:
        vec = zeros(1, bm_rows)
        vec[count] = 1
        svectors_nonlone.append((c, vec))
        count += 1

    svectors_lone = construct_lone_vects(
        benc, sublist_lones_c, uvectorc, kern_c, bm_columns
    )

    (big_matrix, big_uvector) = merge_matrices(
        Mat_c, Mat_k, uvectorc, uvectork, sublist_nonlones_c, sublist_nonlones_k
    )
    kern_bm = big_matrix.nullspace()
    if len(kern_bm) == 0:
        return (None, None, None, None, None)

    kern_vec = select_kern_vec(
        masterkey, special_s, sublist_nonlones_c, kern_bm, big_uvector
    )

    rvectors_nonlone = get_nonlone_vecs(
        kern_vec, kern_c, uvectorc, big_uvector, sublist_nonlones_k
    )
    rvectors_lone = get_lone_vecs(
        kern_vec, big_uvector, sublist_lones_k, sublist_nonlones_c
    )

    output = (
        benc_mats,
        svectors_nonlone,
        svectors_lone,
        rvectors_nonlone,
        rvectors_lone,
    )
    return output


def normalize_substitutions(masterkey, special_s, proofs):
    """
    Ensures that the first entry of the master-key and special non-lone s is 1.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        proofs (list): List of proofs.
    """
    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = (
        proofs
    )

    nm_factor_keys = 1
    nm_factor_ct = 1
    swap = False
    init_key = False
    if rvectors_lone != None:
        for k, vec in rvectors_lone:
            if k == masterkey:
                master_key_vec = vec
                init_key = True

    init_ct = False
    if svectors_nonlone != None:
        for c, vec in svectors_nonlone:
            if c == special_s:
                special_s_vec = vec
                init_ct = True

    ind = 0
    if init_key and init_ct:
        if master_key_vec[0] == 0 or special_s_vec[0] == 0:
            for i in range(len(master_key_vec)):
                if master_key_vec[i] != 0 and special_s_vec[i] != 0:
                    ind = i
                    swap = True
                    nm_factor_keys = master_key_vec[i]
                    nm_factor_ct = special_s_vec[i]
        else:
            nm_factor_keys = master_key_vec[0]
            nm_factor_ct = special_s_vec[0]

        if rvectors_lone != None:
            ctr_vecs = 0
            for k, vec in rvectors_lone:
                if swap:
                    vec = vec.elementary_row_op("n<->m", 0, ind)
                    rvectors_lone[ctr_vecs] = (k, vec)
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_keys)
                    ctr += 1
                ctr_vecs += 1

        if rvectors_nonlone != None:
            for k, vec in rvectors_nonlone:
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_keys)
                    ctr += 1

        if svectors_nonlone != None:
            ctr_vecs = 0
            for c, vec in svectors_nonlone:
                if swap:
                    vec = vec.elementary_col_op("n<->m", 0, ind)
                    svectors_nonlone[ctr_vecs] = (c, vec)
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_ct)
                    ctr += 1
                ctr_vecs += 1

        if svectors_lone != None:
            for c, vec in svectors_lone:
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_ct)
                    ctr += 1

        if swap:
            ctr_rows = 0
            for b, mat in benc_mats:
                mat = mat.elementary_row_op("n<->m", 0, ind)
                benc_mats = (b, mat)
                ctr_rows += 1

    return proofs


# change the inputs of the function to:
# cm, kenc, cenc, cpenc, aenc, benc, unknown
def generate_proof_selective_ven23(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    Generates an AC17 selective proof.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): Selective proof.
    """

    print("\t\t GENERATE PROOF SELECTIVE VEN23 - STARTS HERE")

    kenc = canonical(kenc)
    cenc = canonical(cenc)
    (matk, uvectork) = writeencodingasprod(kenc, unknown)
    (matc, uvectorc) = writeencodingasprod(cenc, unknown)

    Mat_k = Matrix(matk)
    Mat_c = Matrix(matc)

    nonlone_c = determine_non_lone_vars_in_uvector(cenc, benc, uvectorc)

    (sublist_nonlones_c, sublist_lones_c) = sublistslonenonlone(nonlone_c)

    sublist_nonlones_c = put_special_s_first_entry(special_s, sublist_nonlones_c)
    # the function above should not work anymore and should also not be necessary so I think you can comment it out

    # this can also be run with extend_mat_and_vec but yields larger vectors and matrices
    (Mat_c, uvectorc) = extend_mat_and_vec2(Mat_c, uvectorc, benc, sublist_nonlones_c)

    kern_c = Mat_c.nullspace()

    if len(kern_c) == 0:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    (benc_mats, _) = construct_benc_mats(benc, sublist_nonlones_c, uvectorc, kern_c)

    nonlone_k = determine_non_lone_vars_in_uvector(kenc, benc, uvectork)
    # the function above should not be sufficient anymore, because there might be non-lones that occur only in combination with elements in aenc
    # a quick solution could be to replace 'benc' here with 'aenc + benc' but I'm not sure this works

    (sublist_nonlones_k, sublist_lones_k) = sublistslonenonlone(nonlone_k)

    bm_sh = shape(benc_mats[0][1])
    bm_rows = bm_sh[0]
    bm_columns = bm_sh[1]

    svectors_nonlone = []
    count = 0
    for c in sublist_nonlones_c:
        vec = zeros(1, bm_rows)
        vec[count] = 1
        svectors_nonlone.append((c, vec))
        count += 1

    svectors_lone = construct_lone_vects(
        benc, sublist_lones_c, uvectorc, kern_c, bm_columns
    )

    # I think we need to adjust everything from here because we need to also consider the aenc and cpenc encodings
    # I think we might be able to use the following step, and then do another merge with the big matrix below and merge in the matrix for the cp-encodings
    (big_matrix, big_uvector) = merge_matrices(
        Mat_c, Mat_k, uvectorc, uvectork, sublist_nonlones_c, sublist_nonlones_k
    )
    # here needs to go a function that extends the big_matrix and big_uvector with all cp-encodings
    # basically this function just adds all the polynomials in cp-encodings in the rows, and adds monomials in the big_uvector that don't occur there yet
    # you don't need to consider combinations of non-lones because the cp-encodings are already in G_T

    kern_bm = big_matrix.nullspace()
    if len(kern_bm) == 0:
        return (None, None, None, None, None)
    # the code that generates the kernel here can stay

    # TODO
    # this kernel vector selection needs to be rewritten for the generalization.. it should take as input the cm instead of the masterkey and special_s
    # I think we also need aenc and benc here, but I'm not sure yet what the requirements are that we need to pose on the kernel vector
    # kern_vec = select_kern_vec(masterkey, special_s, sublist_nonlones_c, kern_bm, big_uvector)

    # rvectors_nonlone = get_nonlone_vecs(kern_vec, kern_c, uvectorc, big_uvector, sublist_nonlones_k)
    # rvectors_lone = get_lone_vecs(kern_vec, big_uvector, sublist_lones_k, sublist_nonlones_c)

    # output = (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone)
    output = (benc_mats, svectors_nonlone, svectors_lone, [], [])

    return output


def normalize_substitutions_ven23(masterkey, special_s, proofs):
    """
    Ensures that the first entry of the master-key and special non-lone s is 1.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        proofs (list): List of proofs.
    """
    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = (
        proofs
    )

    nm_factor_keys = 1
    nm_factor_ct = 1
    swap = False
    init_key = False
    if rvectors_lone != None:
        for k, vec in rvectors_lone:
            if k == masterkey:
                master_key_vec = vec
                init_key = True

    init_ct = False
    if svectors_nonlone != None:
        for c, vec in svectors_nonlone:
            if c == special_s:
                special_s_vec = vec
                init_ct = True

    ind = 0
    if init_key and init_ct:
        if master_key_vec[0] == 0 or special_s_vec[0] == 0:
            for i in range(len(master_key_vec)):
                if master_key_vec[i] != 0 and special_s_vec[i] != 0:
                    ind = i
                    swap = True
                    nm_factor_keys = master_key_vec[i]
                    nm_factor_ct = special_s_vec[i]
        else:
            nm_factor_keys = master_key_vec[0]
            nm_factor_ct = special_s_vec[0]

        if rvectors_lone != None:
            ctr_vecs = 0
            for k, vec in rvectors_lone:
                if swap:
                    vec = vec.elementary_row_op("n<->m", 0, ind)
                    rvectors_lone[ctr_vecs] = (k, vec)
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_keys)
                    ctr += 1
                ctr_vecs += 1

        if rvectors_nonlone != None:
            for k, vec in rvectors_nonlone:
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_keys)
                    ctr += 1

        if svectors_nonlone != None:
            ctr_vecs = 0
            for c, vec in svectors_nonlone:
                if swap:
                    vec = vec.elementary_col_op("n<->m", 0, ind)
                    svectors_nonlone[ctr_vecs] = (c, vec)
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_ct)
                    ctr += 1
                ctr_vecs += 1

        if svectors_lone != None:
            for c, vec in svectors_lone:
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry / nm_factor_ct)
                    ctr += 1

        if swap:
            ctr_rows = 0
            for b, mat in benc_mats:
                mat = mat.elementary_row_op("n<->m", 0, ind)
                benc_mats = (b, mat)
                ctr_rows += 1

    return proofs


def merge_matrices(matc, matk, uvectorc, uvectork, nonlones_c, nonlones_k):
    """
    Merges the matrix for the ciphertext and key encodings.

    Parameters:
        matc (array): Ciphertext matrix.
        matk (array): Key matrix.
        uvectorc (list): Unknown variables in ciphertext encodings.
        uvectork (list): Unknown variables in key encodings.
        nonlones_c (list): Non-lone ciphertext encodings.
        nonlones_k (list): Non-lone key encodings.
    """
    len_nl_c = len(nonlones_c)
    len_nl_k = len(nonlones_k)
    matc_rows = shape(matc)[0]
    matc_cols = shape(matc)[1]
    matk_rows = shape(matk)[0]
    matk_cols = shape(matk)[1]

    big_uvectorc = []
    for x_k in nonlones_k:
        big_uvectorc += [x_k * i for i in uvectorc]

    big_uvectork = []
    for x_c in nonlones_c:
        big_uvectork += [x_c * i for i in uvectork]

    big_uvector = []
    big_uvector += big_uvectorc
    for x_u in big_uvectork:
        if not x_u in big_uvector:
            big_uvector.append(x_u)

    big_matc = zeros(matc_rows * len_nl_k, matc_cols * len_nl_k)
    big_matk = zeros(matk_rows * len_nl_c, matk_cols * len_nl_c)
    ctr = 0
    for x_k in nonlones_k:
        for i in range(matc_rows):
            for j in range(matc_cols):
                big_matc[i + ctr * matc_rows, j + ctr * matc_cols] += matc[i, j]
        ctr += 1

    ctr = 0
    for x_c in nonlones_c:
        for i in range(matk_rows):
            for j in range(matk_cols):
                big_matk[i + ctr * matk_rows, j + ctr * matk_cols] += matk[i, j]
        ctr += 1

    big_matc_rows = matc_rows * len_nl_k
    big_matk_rows = matk_rows * len_nl_c
    big_mat = zeros(big_matc_rows + big_matk_rows, len(big_uvector))
    i_u = 0
    for x_u in big_uvector:
        i = 0
        for x_c in big_uvectorc:
            if x_u == x_c:
                for j in range(big_matc_rows):
                    big_mat[j, i_u] += big_matc[j, i]
            i += 1

        i = 0
        for x_k in big_uvectork:
            if x_u == x_k:
                for j in range(big_matk_rows):
                    big_mat[j + big_matc_rows, i_u] += big_matk[j, i]
            i += 1

        i_u += 1

    return (big_mat, big_uvector)


def get_nonlone_vecs(kern_vec, kern_c, uvectorc, big_uvector, nonlones_k):
    """
    Generates the vectors for the non-lone variables based on the large kernel

    Parameters:
        kern_vec (list): Kernel vector.
        kern_c (list): Ciphertext-related kernel.
        uvectorc (list): Unknown variables in ciphertext encodings.
        uvectork (list): Unknown variables in key encodings.
        nonlones_k (list): Non-lone key encodings.
    """
    rvectors_nonlone = []
    ctr = 0
    for nl_el in nonlones_k:
        sub_vec = []
        for i in range(ctr, ctr + len(uvectorc)):
            sub_vec.append(kern_vec[i, 0])
        sub_vec = Matrix(sub_vec)

        new_mat = Matrix([vec.transpose() for vec in kern_c + [sub_vec]]).transpose()

        ns_new_mat = new_mat.nullspace()
        for ns_vec in ns_new_mat:
            if ns_vec[-1] != 0:
                ns_vec2 = [-i / ns_vec[-1] for i in ns_vec[:-1]]
                rvectors_nonlone.append((nl_el, Matrix(ns_vec2)))
        ctr += len(uvectorc)

    return rvectors_nonlone


def get_lone_vecs(kern_vec, big_uvector, lones_k, nonlones_c):
    """
    Generates the vectors for the lone variables based on the large kernel

    Parameters:
        kern_vec (list): Kernel vector.
        kern_c (list): Ciphertext-related kernel.
        uvectorc (list): Unknown variables in ciphertext encodings.
        uvectork (list): Unknown variables in key encodings.
        lones_k (list): Lone key encodings.
        nonlones_c (list): Non-lone ciphertext encodings.
    """
    rvectors_lone = []
    for l_el in lones_k:
        rvec = []
        for nl_el in nonlones_c:
            prd = l_el * nl_el
            if prd in big_uvector:
                ind = big_uvector.index(prd)
                rvec.append(kern_vec[ind])
            else:
                rvec.append(0)
        rvectors_lone.append((l_el, Matrix(rvec)))
    return rvectors_lone


def select_kern_vec(masterkey, special_s, nonlones, kern_bm, big_uvector):
    """
    Selects the kern vector that has 1 in the entry corresponding to `alpha * s`
    and 0 in all other combinations of alpha and nonlones.

    Parameters:
        masterkey (sp.core.list.Symbol): Master key descryption.
        special_s (sp.core.list.Symbol): Blinding factor.
        nonlones (list): Non-lone variables.
        kern_bm (list): Kernel.
        big_uvector (list): Unknown variables.
    """
    sub_kern = []
    mk_entry = big_uvector.index(masterkey * special_s)
    null_entries = []
    for el in [i for i in nonlones if i != special_s]:
        if masterkey * el in big_uvector:
            null_entries.append(big_uvector.index(masterkey * el))

    for vec in kern_bm:
        vec_qualified = vec[mk_entry] != 0
        for en in null_entries:
            vec_qualified = vec_qualified and (vec[en] == 0)
        if vec_qualified:
            sub_kern.append(vec)

    if len(sub_kern) > 0:
        kern_vec = sub_kern[0]
        for vec in sub_kern[1:]:
            kern_vec += vec
    else:
        kern_vec = kern_bm[0]

    return kern_vec


def put_special_s_first_entry(special_s, sublist):
    """
    Ensures that the special_s is in the first entry of the sublist.

    Parameters:
        sublist (list): Input sublist.
        special_s (sp.core.list.Symbol): Blinding factor.
    """
    ctr = 0
    entry = 0
    for x_s in sublist:
        if x_s == special_s:
            entry = ctr
        ctr += 1
    cpy_first = sublist[0]
    sublist[0] = special_s
    sublist[entry] = cpy_first
    return sublist


def extend_mat_and_vec(matc, uvectorc, benc, nonlones):
    """
    Extends the matrix and uvector with combinations that are not in the encodings.

    Parameters:
        matc (array): Input matrix.
        uvectorc (list): List uf unkown variables.
        benc (list): Public key encodings.
        nonlones (list): Non-lone variables.
    """
    zero_vec = zeros(shape(matc)[0], 1)
    nr_cols = shape(matc)[1]
    for x_b in benc:
        for x_c in nonlones:
            prod = x_b * x_c
            if not prod in uvectorc:
                uvectorc.append(prod)
                matc = matc.col_insert(nr_cols, zero_vec)
                nr_cols += 1
    return (matc, uvectorc)


def extend_mat_and_vec2(matc, uvectorc, benc, nonlones):
    """
    Extends the matrix and uvector with common variables that are not in the encodings

    Parameters:
        matc (array): Input matrix.
        uvectorc (list): List uf unkown variables.
        benc (list): Public key encodings.
        nonlones (list): Non-lone variables.
    """
    zero_vec = zeros(shape(matc)[0], 1)
    nr_cols = shape(matc)[1]
    spec_s = nonlones[0]
    for x_b in benc:
        b_in_uvec = False
        for x_c in nonlones:
            prod = x_b * x_c
            if prod in uvectorc:
                b_in_uvec = True
        if not b_in_uvec:
            uvectorc.append(x_b * spec_s)
            matc = matc.col_insert(nr_cols, zero_vec)
            nr_cols += 1
    return (matc, uvectorc)


def sublistslonenonlone(list_lone_nonlone):
    """
    Separates the list of lone and non-lone variables in two sublists.

    Parameters:
        list_lone_nonlone (list): List of lone and lone-lone variables.

    Returns:
        (list): List of lone variables.
        (list): List of non-lone variables.
    """
    sublist_nonlones = []
    sublist_lones = []
    for c, nonlone in list_lone_nonlone:
        if nonlone:
            sublist_nonlones.append(c)
        else:
            sublist_lones.append(c)
    return (sublist_nonlones, sublist_lones)


def construct_benc_mats(benc, nonlonesub, uvector, kern):
    """
    Constructs the matrices for the common variables b implied by mpk.

    Parameters:
        benc (list): List of public key encodings.
        nonlonesub (list): List of non-lone variables.
        uvector (list): List of unknown variables.
        kern (list): Kernel.

    Returns:
        (list): Matrix for the common variable b.
        (list): List of variables not in b.
    """
    benc_mats = []
    notinit_b = []
    for bx in benc:
        bx_not_in_benc = True
        bmat = [[0 for i in kern] for j in nonlonesub]
        count = 0
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono, lis)
                if bx in lis and len(lis) == 2:
                    bx_not_in_benc = False
                    sindex = 1 - lis.index(bx)
                    svar = lis[sindex]
                    row_s = nonlonesub.index(svar)
                    count_kern = 0
                    for v in kern:
                        bmat[row_s][count_kern] = v.row(count)[0]
                        count_kern += 1
            count += 1
        if bx_not_in_benc:
            notinit_b.append(bx)
        else:
            bmat = Matrix(bmat)
            benc_mats.append((bx, bmat))
    return (benc_mats, notinit_b)


def construct_lone_vects(benc, lonesub, uvector, kern, len_vec):
    """
    Constructs the vectors for the lone variables associated with the ciphertext
    (or key in the case of co-selective security).

    Parameters:
        benc (list): List of public key encodings.
        lonesub (list): List of lone variables.
        uvector (list): List of unknown variables.
        kern (list): Kernel.
        len_vec: Length of vector.

    Returns:
        (list): Lone variables vector.
    """
    lone_vects = []
    for slone in lonesub:
        svec = [0 for i in range(len_vec)]
        count = 0
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono, lis)
                if slone in lis and len(lis) == 1:
                    row_s = lonesub.index(slone)
                    for i in range(len(kern)):
                        svec[i] = kern[i].row(count)[0]
            count += 1
        svec = Matrix([svec])  # .transpose()
        lone_vects.append((slone, svec))
    return lone_vects


def determine_non_lone_vars_in_uvector(enc, benc, uvector):
    """
    Returns a list of non-lone variables that occur in the uvector.

    Parameters:
        enc (list): List of encodings.
        benc (list): List of public key encodings.
        uvector (list): List of unknown variables.

    Returns:
        (list): Non-Lone variables in unknown vector.
    """
    list_non_common_vars = []
    for mono in uvector:
        if type(mono) != int:
            lis = []
            recovervars(mono, lis)
            for x in lis:
                if not x in benc and not x in list_non_common_vars:
                    list_non_common_vars.append(x)
    list_nonlone = []
    for x in list_non_common_vars:
        non_lone = False
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono, lis)
                if x in lis:
                    for y in lis:
                        if y in benc:
                            non_lone = True
        list_nonlone.append((x, non_lone))
    return list_nonlone


def check_kernel_products(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    Checks whether the kernel contains vectors that are not zero in the important entries.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.

    Returns:
        (list): Equations found.
        (list): Equations.
    """
    kenc = canonical(kenc)
    cenc = canonical(cenc)

    penc = []
    for k_el in kenc:
        for c_el in cenc:
            penc.append(cancel(k_el * c_el))

    (mat, uvector) = writeencodingasprod(penc, unknown)

    BigMat = Matrix(mat)

    mk_index = 0
    ctr = 0
    for el in uvector:
        if el == masterkey * special_s:
            mk_index = ctr
        ctr += 1

    kern = BigMat.nullspace()

    eqs = []
    eqsfound = False
    for vec in kern:
        if vec[mk_index] != 0:
            eqsfound = True
            eqs.append(vec[mk_index])
    return (eqsfound, eqs)


if __name__ == "__main__":

    # Wat11

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, b2, r, rp, x, y, s, sp"
    )

    k1 = alpha + r * b
    k2 = r * b0
    k3 = r
    c1 = s * b + sp * b1
    c2 = s
    c3 = sp
    c4 = s * b + sp * b2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = 1
    mpk5 = b2

    # known values: x, y

    unknown = [alpha, b, b0, b1, b2, r, s, sp]

    k = [k1, k2, k3]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk5]

    # generate_the_proofs(alpha, s, k, c, mpk, unknown)
    # print(generate_proof_selective(k, c, mpk, unknown))

    # RW13

    alpha, b, bp, b0, b1, r, rp, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, x, y, s, sp"
    )

    k1 = alpha + r * b
    k2 = r * bp + rp * (b0 + y * b1)
    k3 = r
    k4 = rp
    c1 = s * b + sp * bp
    c2 = sp * (b0 + x * b1)
    c3 = s
    c4 = sp
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = bp

    # known values: x, y

    unknown = [alpha, b, b0, b1, bp, r, rp, s, sp]

    k = [k1, k2, k3, k4]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk4]

    pprint(generate_proof_selective(alpha, s, k, c, mpk, unknown))

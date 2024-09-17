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

"""common.py: general methods for dealing with symbols in the attack
and analysis implementations"""

from sympy import *

init_printing(use_unicode=True)


def findsymb(f, g):
    """
    Adds the symbols occurring in f to g

    Parameters:
        f (list of sp.core.list.Symbol): first expression
        g (list of sp.core.list.Symbol): second expression
    """
    if f.func == Symbol:
        g.append(f)
    else:
        for fp in f.args:
            findsymb(fp, g)


def intersectnotempt(lis1: list, lis2: list) -> bool:
    """
    Checks if the intersection of lis1 and lis2 is not empty.

    Parameters:
        list1 (list): First list
        list2 (list): Second list

    Returns:
        (bool): According to the intersection of lis1 and list2
    """
    for f in lis1:
        if f in lis2:
            return True
    return False


def decompose(lisi: list, unknown) -> list:
    """
    Decomposes list lisi of variables in two lists:
    k = list of known variables and u = list of unknown variables

    Parameters:
        lisi (list): List of variables
        unknown (list): Unkonwn variables

    Returns:
        (bool): According to the intersection of lis1 and list2
    """

    k = []
    u = []
    for f in lisi:
        g = []
        findsymb(f, g)
        if intersectnotempt(g, unknown):
            u.append(f)
        else:
            k.append(f)
    return [k, u]


def recovervars(mono, lis: list) -> None:
    """
    Adds the variables of a monomial to list lis

    Parameters:
        mono (list): Monomial
        lis (list): List to add teh variables
    """
    if mono.func == Mul:
        for f in mono.args:
            recovervars(f, lis)
    else:
        lis.append(mono)


def recovermonos(ar, col: list) -> None:
    """
    Returns a list of monomials of a given polynomial ar

    Parameters:
        ar (list): Input polynomial
        col (list): List of monomials of polynomial ar
    """
    if type(ar) != int:
        if ar.func == Add:
            for f in ar.args:
                col.append(recovermonos(f, col))
        else:
            col.append(ar)


def invector(f, vec):
    """
    Checks if the monomial f is already in vec

    Parameters:
        f (list): Monomial f
        vec (list): Input vector
    """
    fmul = 1
    for g in f:
        fmul = Mul(fmul, g)
    c = 0
    for fp in vec:
        if fmul == fp:
            return (True, c, fmul)
        c += 1
    return (False, -1, fmul)


def addcomptodecomp(kvector: list, uvector: list, toadd) -> None:
    """
    Adds a new monomial split in a known and unknown part to kvector and uvector

    Parameters:
        kvector (list): Known vector of variables
        uvector (list): Unknown vector of variables
        toadd (list): Monomial split
    """
    [k, u] = toadd
    (b, c, umul) = invector(u, uvector)
    kmul = 1
    for g in k:
        kmul = Mul(kmul, g)
    if b:
        kvector[c] = Add(kvector[c], kmul)
    else:
        kvector.append(kmul)
        uvector.append(umul)


def appendzeros(mat, uvector: list) -> None:
    """
    Takes a matrix as input and makes each row as long as uvector

    Parameters:
        mat (array): Input matrix
        uvector (list): Unknown vector of variables
    """
    l = len(uvector)
    for f in mat:
        while len(f) < l:
            f.append(0)


def writepolyasprod(poly, uvector: list, unknown: list) -> None:
    """
    This takes as input a polynomial, and a set of unknown variables.
    It outputs a vector decomposition, where the kvector consists of
    integers and known variables, and the uvector of unknown variables.

    Parameters:
        poly (sp.core.list.Symbol): Polynomial expression.
        uvector (list): Vector decomposition.
        unknown (list): Vector of unknown variables.
    """
    colmono = []
    # this recovers a list colmono of monomials
    recovermonos(poly, colmono)
    cmcpy = []
    # this eliminates all occurrences of 'None'
    for f in colmono:
        if not (f == None):
            cmcpy.append(f)
    variables = []
    # for each monomial in the list, we:
    for mono in cmcpy:
        lis = []
        # recover a list of the variables
        recovervars(mono, lis)
        # note that variables is a list of lists of variables
        # the first entry is the list of variables of the first monomial, etc.
        variables.append(lis)
    kvector = [0 for x in uvector]
    # for each list of variables f
    for f in variables:
        # we decompose it into a subset of known and subset of unknown variables
        liso = decompose(f, unknown)
        # we add the decomposition to the known and uknown-variable vector
        # this is done by first checking wether the product of the unknown
        # variables is already in uvector or not
        addcomptodecomp(kvector, uvector, liso)
    return kvector


def writeencodingasprod(enco: list, unknown: list) -> tuple[list, list]:
    """
    This takes as input an encoding and a set of unknown variables.
    It outputs a matrix decomposition, where the matrix consists of
    integers and known variables, and the vector of unknown variables.

    Parameters:
        enco (list): Input encoding.
        unknown (list): Vector of unknown variables.
    """
    uvector = []
    mat = []
    for poly in enco:
        mat.append(writepolyasprod(poly, uvector, unknown))
    appendzeros(mat, uvector)
    return (mat, uvector)


def canonical(listpolys: list) -> list:
    """
    First ensure that all polynomials are in canonical form.

    Parameters:
        listpolys (list): List of poynomials.

    Returns:
        (list): List of polynomials in canonical form.
    """
    copylist = []
    for x in listpolys:
        x = x.expand()
        copylist.append(x)
    return copylist


def reordermatuvec(masterkey, mat, uvector: list):
    """
    Reordering matrix and uvector so master key is in first entry.

    Parameters:
        masterkey (sp.core.list.Symbol): List of poynomials.
        uvector (list): List of unkonwn variables.

    Returns:
        (bool): The master key was identified.
        (array): Matrix reordered so mater key is in the first entry.
        (list): List of unkown variables.
    """
    mk_found = False

    if uvector[0] == masterkey:
        mk_found = True
        return (mk_found, mat, uvector)
    c = 0
    for u in uvector:
        if u == masterkey:
            cp = c
            mk_found = True
        c += 1

    if mk_found:
        uvector = [uvector[cp]] + uvector[:cp] + uvector[cp + 1 :]
        matcpy = []
        for lis in mat:
            lis = [lis[cp]] + lis[:cp] + lis[cp + 1 :]
            matcpy.append(lis)
        return (mk_found, matcpy, uvector)

    return (mk_found, mat, uvector)


def is_var_denom(var) -> bool:
    """
    It detects if a variable is part of the
    denominator.

    Parameters:
        var (sp.core.list.Symbol): Input variable.

    Returns:
        (bool): Result of checking if a variable is part of the denominator.
    """
    if var.func == Pow:
        if var.args[1] == -1:
            return True
    return False


def is_var_not_in_list(var, lis) -> bool:
    """
    It detects if a variable doesn't belong
    to a list.

    Parameters:
        var (sp.core.list.Symbol): Input variable.
        lis (list): List of sympy expressions.

    Returns:
        (bool): Result of check.
    """
    for varx in lis:
        if var == varx:
            return False
    return True


def var_contains_unknown(var, unknowns: list) -> bool:
    """
    It detects if a sympy variable is part of the
    unknowns.

    Parameters:
        var (sp.core.list.Symbol): Input variable.
        unknown (list): List of unknowns as sympy expressions.

    Returns:
        (bool): Result of check.
    """
    if var.func == Symbol:
        return var in unknowns

    for x in var.args:
        if x.args:
            for y in x.args:
                if y in unknowns:
                    return True
        if x in unknowns:
            return True
    return False


def collect_denoms(lis: list, unknowns: list) -> list:
    """
    Collects the denominators of the encodings
    not to be confused with demons

    Parameters:
        lis (list): Input list of sp.core.list.Symbol expressions.
        unknown (list): List of unknowns as sympy expressions.

    Returns:
        (list): List of denominators.
    """
    ## this part is the same as in writepolyasprod
    colmono = []
    for poly in lis:
        recovermonos(poly, colmono)
        cmcpy = []
    for f in colmono:
        if not (f == None):
            cmcpy.append(f)
    variables = []
    for mono in cmcpy:
        recovervars(mono, variables)
    denoms = []
    for var in variables:
        if is_var_denom(var):
            if var_contains_unknown(var.args[0], unknowns):
                if is_var_not_in_list(var.args[0], denoms):
                    denoms.append(var.args[0])
    return denoms


def denoms_prod(denoms: list):
    """
    Computes the product of denoms

    Parameters:
        denoms (list): Product of denominators.

    Returns:
        (list): Product of denominators.
    """
    denomprod = 1
    for denom in denoms:
        denomprod = Mul(denomprod, denom)
    return denomprod


def find_attack_row(mat):
    """
    Given a matrix finds the
    attack row.

    Parameters:
        matrix (array): Input matrix.

    Returns:
        (bool): If a row can be attacked.
        (list): Row.
    """
    nr_rows = shape(mat)[0]

    if nr_rows == 0:
        return True, None

    for i in range(nr_rows):
        row = mat.row(i)
        if row[-1] != 0:
            return False, (-row / row[-1])[:-1]
    return False, 0 * row[:-1]


def merge_lists(lis1, lis2):
    """
    Merges two lists of sp.core.list.Symbol expresions.

    Parameters:
        lis1 (list): List of sp.core.list.Symbol expresions.
        lis2 (list): List of sp.core.list.Symbol expresions.

    Returns:
        (list): Merged list.
    """
    lis3 = []
    for elem in lis1 + lis2:
        if not elem in lis3:
            lis3.append(elem)
    return lis3


def gen_all_p(k, c, mpk, gp):
    """
    Gives all possible products that an attacker can generate.

    Parameters:
        k (list): List of key encodings.
        c (list): List of ciphertext encodings.
        mpk (list): List of MPK encodings.
        gp (list): List of global parameter encodings.
    Returns:
        (list): All possible combinations of encodings.
    """

    # k*c

    all_k_c = []
    for i in k:
        for j in c:
            all_k_c.append(i * j)

    # k*mpk

    all_k_mpk = []
    for i in k:
        for j in mpk:
            all_k_mpk.append(i * j)

    # c*mpk

    all_mpk_c = []
    for i in c:
        for j in mpk:
            all_mpk_c.append(i * j)

    # c*gp

    all_gp_c = []
    for i in c:
        for j in gp:
            all_gp_c.append(i * j)

    # k*gp

    all_gp_k = []
    for i in k:
        for j in gp:
            all_gp_k.append(i * j)

    return all_k_c + all_k_mpk + all_mpk_c + all_gp_c + all_gp_k


def transform_encoding_list(denomprod, p):
    """
    Normalizes the encoding list with respect to the denominators.

    Parameters:
        denomprod (list): List of denominators.
        p (list): Encoding list.

    Returns:
        (list): Transformed encoding list.
    """
    pcpy = []

    for pp in p:
        pcpy.append(cancel(pp * denomprod))

    return canonical(pcpy)


def get_vars_polynomial(poly):
    """
    Returns a list of variables occuring in the polynomial poly.

    Parameters:
        poly (list): Polynomial.

    Returns:
        (list): List of variables occuring in poly.
    """
    monos = []
    recovermonos(poly, monos)
    monos_cpy = []
    for f in monos:
        if f != None:
            monos_cpy.append(f)
    monos = monos_cpy
    lis_vars = []
    for mono in monos:
        recovervars(mono, lis_vars)

    lis_vars_cpy = []
    for elem in lis_vars:
        if not elem in lis_vars_cpy:
            lis_vars_cpy.append(elem)
    return lis_vars_cpy


def get_vars_list_polynomials(polys):
    """
    Returns list of variables occuring in the list of polynomials.

    Parameters:
        polys (list): Polynomial.

    Returns:
        (list): List of variables occuring in poly.
    """
    lis_vars = []
    for poly in polys:
        lis_vars += get_vars_polynomial(poly)
    return lis_vars


def trim_matrix_and_uvector(mat, uvec):
    """
    Removes the rows in the matrix that do not contribute an attack.

    Parameters:
        mat (array): Attacking matrix.
        uvec: Unknown vector.

    Returns:
        (array): Matrix after trimming.
    """
    nr_rows = shape(mat)[0]
    nr_columns = shape(mat)[1]
    rows_to_delete = []
    cols_to_delete = []

    for jind in range(nr_columns):
        ctr = 0
        last_iind = 0
        for iind in range(nr_rows):
            if mat[iind, jind] != 0:
                ctr += 1
                last_iind = iind
        if ctr == 1:
            if not last_iind in rows_to_delete:
                rows_to_delete.append(last_iind)
            cols_to_delete.append(jind)

    for jind in reversed(cols_to_delete):
        mat.col_del(jind)
        del uvec[jind]

    rows_to_delete2 = []
    for ind in reversed(range(nr_rows - 1)):
        if ind in rows_to_delete:
            rows_to_delete2.append(ind)

    for ind in rows_to_delete2:
        mat.row_del(ind)

    return (mat, uvec, rows_to_delete2, reversed(cols_to_delete))

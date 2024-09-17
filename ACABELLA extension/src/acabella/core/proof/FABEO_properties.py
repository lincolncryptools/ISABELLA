# -*- coding: utf-8 -*-

from acabella.core.common.utils import *
from sympy import *
from acabella.core.proof.trivial_security_and_collusion import *

init_printing(use_unicode=True)


def FABEO_properties(masterkey, special_s, kenc, cenc, benc, unknown) -> str:
    """
    This is the main function that checks whether the FABEO property is satisfied.

    Parameters:
        masterkey (sp.core.list.Symbol): Master key description
        special_s (sp.core.list.Symbol): Blinding value description.
        kenc (list of sp.core.list.Symbol): Key encodings,
        cenc (list of sp.core.list.Symbol): Ciphertext encodings.
        benc (list of sp.core.list.Symbol): Common variable encodings.
        unknown (list of sp.core.list.Symbol): List of unknown variables.

    Returns:
        (str): The result of the checking the FABEO property.
    """

    process_log = []

    (correct, kenc, cenc) = correct_form_silent(kenc, cenc, benc, unknown)

    blindingvalue = masterkey * special_s

    (nonlones_c, nonlones_k, cpolys, kpolys) = determine_nonlones_and_polys(
        masterkey, special_s, kenc, cenc, benc, unknown
    )

    penc = compute_products_ac17(kpolys, cpolys, nonlones_k, nonlones_c)

    (mat, uvector) = writeencodingasprod(penc, unknown)

    mat = Matrix(mat)

    target_vector = Matrix([writepolyasprod(blindingvalue, uvector, unknown)])

    list_bv_indices = []
    ctr = 0
    for elem in target_vector:
        if elem != 0:
            list_bv_indices.append(ctr)
        ctr += 1

    (lis_masterkeys, lis_vars_kenc, lis_vars_cenc, lis_vars_benc) = obtain_masterkeys(
        blindingvalue, kenc, cenc, benc, unknown
    )

    lis_shared_indices = []
    for ind in range(len(uvector)):
        vars_elem = get_vars_polynomial(uvector[ind])
        is_shared = True
        for var in vars_elem:
            if (
                (var in lis_vars_kenc)
                and not (var in lis_vars_benc)
                and not (var in lis_masterkeys)
            ):
                is_shared = False
        if is_shared:
            lis_shared_indices.append(ind)

    lis_shared_indices_not_bv = [
        ind for ind in lis_shared_indices if not ind in list_bv_indices
    ]

    rs_shared = []
    for ind in lis_shared_indices:
        vec = zeros(1, len(uvector))
        vec[ind] = 1
        rs_shared.append(vec)

    rank_rs_s = Matrix(rs_shared).rank()
    mat_rs = mat.rowspace()
    rank_rs = Matrix(mat_rs).rank()

    rank_both = Matrix(rs_shared + mat_rs).rank()

    if rank_both == rank_rs_s + rank_rs:
        # print("\t The scheme satisfies the FABEO property and is thus secure against collusion. \n")
        process_log.append(
            "\t The scheme satisfies the FABEO property and is thus secure against collusion. \n"
        )
        process_log += print_transcript_of_FABEO_property(
            mat, uvector, lis_shared_indices
        )
    else:
        # print("\t The scheme does not satisfy the FABEO property. \n")
        process_log.append("\t The scheme does not satisfy the FABEO property. \n")

    return "\n".join(process_log)


def compute_products_ac17(kpolys, cpolys, knons, cnons):
    """
    This function computes all products of non-lone variables and encoding polynomials

    Parameters:
        kpolys (list): Key encoding polynomial.
        cpolys (list): Ciphertext encoding polynomial.
        knons (list): Key non-lone variables.
        cnons (list): Ciphertext non-lone variables.

    Returns:
        (list): Products.
    """

    prods = []
    for x_k in knons:
        for poly_c in cpolys:
            prods.append(cancel(x_k * poly_c))
    for x_c in cnons:
        for poly_k in kpolys:
            prods.append(cancel(x_c * poly_k))
    return prods


def determine_nonlones_and_polys(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    This function determines the non-lone variables and the encoding polynomials

    Parameters:
        masterkey (sp.core.list.Symbol): Master key description
        special_s (sp.core.list.Symbol): Blinding value description.
        kenc (list of sp.core.list.Symbol): Key encodings,
        cenc (list of sp.core.list.Symbol): Ciphertext encodings.
        benc (list of sp.core.list.Symbol): Common variable encodings.
        unknown (list of sp.core.list.Symbol): List of unknown variables.

    Returns:
        (list): Non-lone ciphertext variables.
        (list): Non-lone key variables.
        (list): Ciphertext encoding polynomials.
        (list): Key encoding polynomials.
    """

    (matk, uvectork) = writeencodingasprod(kenc, unknown)
    (matc, uvectorc) = writeencodingasprod(cenc, unknown)

    matk = Matrix(matk)
    matc = Matrix(matc)

    nonlone_c = determine_non_lone_vars_in_uvector(cenc, benc, uvectorc)

    (sublist_nonlones_c, sublist_lones_c) = sublistslonenonlone(nonlone_c)

    sublist_nonlones_c = put_special_s_first_entry(special_s, sublist_nonlones_c)

    nonlone_k = determine_non_lone_vars_in_uvector(kenc, benc, uvectork)

    (sublist_nonlones_k, sublist_lones_k) = sublistslonenonlone(nonlone_k)

    kpolys = [k_poly for k_poly in kenc if not k_poly in sublist_nonlones_k]
    cpolys = [c_poly for c_poly in cenc if not c_poly in sublist_nonlones_c]

    return (sublist_nonlones_c, sublist_nonlones_k, cpolys, kpolys)


def print_transcript_of_FABEO_property(mat, uvector, lis_shared) -> str:
    """
    This function generates a transcript that proves that the encodings satisfy the FABEO property.

    Parameters:
        mat (array): Matrix.
        uvector (list): Unknown variables.
        lis_shared (list): Shared variables.

    Returns:
        (str): Transcript of FABEO property.
    """
    transcript_log = []
    msg = "\t Generating transcript that proves that the FABEO property holds.."
    kern = mat.nullspace()
    kern_short = []
    for vec in kern:
        vec_r = []
        ctr = 0
        for el in vec:
            if ctr in lis_shared:
                vec_r.append(el)
            ctr += 1
        kern_short.append(Matrix(vec_r))

    err_sol_not_found = False
    kern_new = []
    ctr = 0
    for ind in lis_shared:
        vec = zeros(len(lis_shared), 1)
        vec[ctr] = 1
        ks_new = Matrix([vec1.transpose() for vec1 in kern_short + [vec]]).transpose()
        kern_ks_new = ks_new.nullspace()
        sol_found = False
        for kern_vec in kern_ks_new:
            if kern_vec[-1] != 0:
                sol_found = True
                val = -kern_vec[-1]
                sol_vec = [entry / val for entry in kern_vec]
        if sol_found:
            new_kern_vec_long = kern[0] * sol_vec[0]
            for ind in range(1, len(kern)):
                new_kern_vec_long += kern[ind] * sol_vec[ind]
            kern_new.append(new_kern_vec_long)
        else:
            err_sol_not_found = True
        ctr += 1

    if err_sol_not_found:
        msg += "\n\t Transcript not found.."
        return msg

    msg += (
        "\n\t\t For the transcript, we use the following reference vector of monomials: \n\t\t\t"
        + str(uvector)
    )

    transcript_log.append(msg)

    ctr = 0
    for ind in lis_shared:
        msg = "\n\t\t The vector with 1 in the entry corresponding to " + str(
            uvector[ind]
        )
        if len(lis_shared) > 2:
            msg += " and 0 in the entries corresponding to "
        else:
            msg += " and 0 in the entry corresponding to "
        first = True
        for ind1 in lis_shared:
            if ind1 != ind:
                if not first:
                    msg += ","
                else:
                    first = False
                msg += str(uvector[ind1])
        msg += " is: \n\t\t\t"
        msg += str(list(kern_new[ctr]))
        transcript_log.append(msg)
        # ideally, str(list(kern_new[ctr])) should be added without casting the vector as a string and list
        # transcript_log.append(kern_new[ctr]))
        ctr += 1

    return transcript_log


if __name__ == "__main__":

    # Wat11

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

    # generate_the_proofs(alpha, s, k, c, mpk, unknown)
    FABEO_properties(alpha, s, k, c, mpk, unknown)

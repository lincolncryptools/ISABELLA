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

init_printing(use_unicode=True)


## The first two functions are for the AC17 case ##
# verifies the trivial security of a scheme that satisfies the AC17 form
def verify_trivial_security(
    masterkey, special_s, kenc, cenc, benc, unknown, controlled, constraints
):

    msg_log = []

    (eqsfound, eqs_to_analyze) = check_kernel_products(
        masterkey, special_s, kenc, cenc, benc, unknown
    )
    if not eqsfound:
        # print("\n\t Failed!")
        msg_log.append("\n\t Failed!")
        return False
    else:
        at_least_one_nonzero = False
        for eq in eqs_to_analyze:
            if eq != 0:
                at_least_one_nonzero = True
        # print("\n\t Passed! The security of the scheme depends on whether at least one of the following assumption(s) holds:")
        msg_log.append(
            "\n\t Passed! The security of the scheme depends on whether at least one of the following assumption(s) holds:"
        )
        ctr = 1
        for eq in eqs_to_analyze:
            if type(eq) != int:
                # print("\n\t\t (" + str(ctr) + ") " + str(eq) + " != 0")
                msg_log.append("\n\t\t (" + str(ctr) + ") " + str(eq) + " != 0")
                ctr += 1
        if ctr == 1:
            # print("\n\t\t None")
            msg_log.append("\n\t\t None")

        return at_least_one_nonzero, "\n".join(msg_log)


# verifies security against collusion of a scheme that satisfies the AC17 form
# uses the security proofs for this, which implies the collusion-security check
# in the generalized variant of this function
def generate_the_proofs_and_check_collusion(
    masterkey, special_s, kenc, cenc, benc, unknown
):

    process_log = []

    (correct, kenc, cenc) = correct_form_silent(kenc, cenc, benc, unknown)
    collusion_secure = False
    if correct:
        output = generate_proof_selective(
            masterkey, special_s, kenc, cenc, benc, unknown
        )
        output = normalize_substitutions(masterkey, special_s, output)
        if output[0] != None:
            result, tmp_log = verify_collusion_security_only(
                masterkey, special_s, kenc, cenc, benc, output
            )
            process_log.append(tmp_log)

            if not result:
                # print("\n\t [!] The scheme is possibly insecure against collusion! \n")
                process_log.append(
                    "\n\t [!] The scheme is possibly insecure against collusion! \n"
                )
        else:
            result = False
            # print("\n\t [!] No selective proof found. The scheme is possibly insecure against collusion! \n")
            process_log.append(
                "\n\t [!] No selective proof found. The scheme is possibly insecure against collusion! \n"
            )

        output2 = generate_proof_co_selective(
            masterkey, special_s, kenc, cenc, benc, unknown
        )
        output2 = normalize_substitutions(masterkey, special_s, output2)
        if output2[0] != None:
            result2, log = verify_proof(masterkey, special_s, kenc, cenc, benc, output2)
            process_log.append(log)
            if result and result2:
                # print("\n\t The scheme satisfies our collusion property and is thus secure against collusion. \n")
                process_log.append(
                    "\t The scheme satisfies our collusion property and is thus secure against collusion. \n"
                )
                collusion_secure = True
            else:
                # print("\n\t [!] The scheme is possibly insecure against collusion! \n")
                process_log.append(
                    "\n\t [!] The scheme is possibly insecure against collusion! \n"
                )
        else:
            # print("\n\t [!] No co-selective proof found. The scheme is possibly insecure against collusion! \n")
            process_log.append(
                "\n\t [!] No co-selective proof found. The scheme is possibly insecure against collusion! \n"
            )
    return collusion_secure, "\n".join(process_log)


## The functions below are for the generalized functionalities and work for all schemes, not just AC17 ones. ##


# verifies the trivial security of the scheme
# the blinding value is what masks the message
def verify_trivial_security_generalized(blindingvalue, kenc, cenc, benc, unknown):

    string_list = []

    penc = gen_all_p(kenc, cenc, benc, [])
    penc = canonical(penc)

    denoms = collect_denoms(penc, unknown)
    denomprod = denoms_prod(denoms)
    penc = transform_encoding_list(denomprod, penc)
    blindingvalue = canonical([cancel(blindingvalue * denomprod)])[0]

    (mat, uvector) = writeencodingasprod(penc, unknown)
    mat = Matrix(mat)

    luvec1 = len(uvector)
    target_vector = Matrix([writepolyasprod(blindingvalue, uvector, unknown)])
    luvec2 = len(uvector)
    if luvec1 != luvec2:
        # print("\n\t Passed! The blinding value contains terms that cannot be created with the rest of the ciphertext and the key. However, because of this property, collusion security cannot be verified.")
        string_list.append(
            "\n\t Passed! The blinding value contains terms that cannot be created with the rest of the ciphertext and the key. However, because of this property, collusion security cannot be verified."
        )
        return (False, None, None, None, None, "\n".join(string_list))

    list_bv_indices = []
    ctr = 0
    for elem in target_vector:
        if elem != 0:
            list_bv_indices.append(ctr)
        ctr += 1

    kern = mat.nullspace()

    kern_red = []
    kern_remainder = []
    for vec in kern:
        at_least_one_zero = False
        for ind in list_bv_indices:
            if vec[ind] != 0:
                at_least_one_zero = True
        if at_least_one_zero:
            kern_red.append(vec)
        else:
            kern_remainder.append(vec)

    if len(kern_red) == 0:
        # print("\n\t Failed!")
        string_list.append("\n\t Failed!")
        return (False, None, None, None, None, "\n".join(string_list))

    # print("\n\t If there exists a solution for the following system of equations:")
    msg = ""
    ctr = 1
    ctr2 = 0
    for ind in range(len(list_bv_indices)):
        msg2 = "\n\t\t (" + str(ctr) + ") "
        first = True
        at_least_one_nonzero = False
        for ind2 in range(len(kern_red)):
            eq_is_zero = False
            el = cancel(kern_red[ind2][list_bv_indices[ind]])
            if not el.is_integer:
                eq = "(" + str(el) + ")"
                at_least_one_nonzero = True
            else:
                if el != 0:
                    eq = str(el)
                    at_least_one_nonzero = True
                else:
                    eq_is_zero = True

            if not eq_is_zero:
                if not first:
                    msg2 += " + c" + str(ind2) + "*" + eq
                else:
                    msg2 += " c" + str(ind2) + "*" + eq
                    first = False
        if at_least_one_nonzero:
            msg2 += " = " + "d" + str(ctr2)  # str(target_vector[list_bv_indices[ind]])
            msg += msg2
        else:
            msg += (
                msg2 + " 0 = " + "d" + str(ctr2)
            )  # + str(target_vector[list_bv_indices[ind]])
        ctr += 1
        ctr2 += 1

    msg2 = "\n\t\t (" + str(ctr) + ") "
    ctr3 = 0
    first = True
    for ind in range(len(list_bv_indices)):
        if not first:
            msg2 += " +"
        else:
            first = False
        el = target_vector[list_bv_indices[ind]]
        if not el.is_integer:
            msg2 += " d" + str(ctr3) + "*(" + str(el) + ")"
        else:
            msg2 += " d" + str(ctr3) + "*" + str(el)
        ctr3 += 1
    msg2 += " != 0"
    msg += msg2

    # print(msg)
    string_list.append(msg)
    if len(kern_red) > 1:
        if len(kern_red) > 2:
            cstring = "c0,...,c" + str(len(kern_red) - 1) + ","
        else:
            cstring = "c0,c1,"
    else:
        cstring = "c0,"

    if len(list_bv_indices) > 1:
        if len(list_bv_indices) > 2:
            dstring = "d0,...,d" + str(len(list_bv_indices) - 1)
        else:
            dstring = "d0,d1"
    else:
        dstring = "d0"

    # print("\n\t where " + cstring + dstring + " denote the coefficients, then the scheme is trivially secure.")
    string_list.append(
        "\n\t where "
        + cstring
        + dstring
        + " denote the coefficients, then the scheme is trivially secure."
    )

    kern_red2 = []
    for vec in kern_red:
        if sum(target_vector[i] * vec[i] for i in range(len(target_vector))) != 0:
            kern_red2.append(vec)

    if len(kern_red2) > 0:
        return (
            True,
            kern_red + kern_remainder,
            uvector,
            target_vector,
            list_bv_indices,
            "\n".join(string_list),
        )
    else:
        return (
            False,
            kern_red + kern_remainder,
            uvector,
            target_vector,
            list_bv_indices,
            "\n".join(string_list),
        )


# obtains the master keys from the encodings
def obtain_masterkeys(blindingvalue, kenc, cenc, benc, unknown):
    lis_vars_blindingvalue = get_vars_polynomial(blindingvalue)
    lis_vars_kenc = get_vars_list_polynomials(kenc)
    lis_vars_cenc = get_vars_list_polynomials(cenc)
    lis_vars_benc = get_vars_list_polynomials(benc)

    lis_masterkeys = []
    for elem in lis_vars_blindingvalue:
        is_unknown = elem in unknown
        in_key = elem in lis_vars_kenc
        not_in_cenc = not (elem in lis_vars_cenc)
        not_in_benc = not (elem in lis_vars_benc)
        if is_unknown and in_key and not_in_cenc and not_in_benc:
            lis_masterkeys.append(elem)
    return (lis_masterkeys, lis_vars_kenc, lis_vars_cenc, lis_vars_benc)


# removes all the kernel vectors that are all-zero in the given indices
def reduce_kern(indices, kern):
    new_kern = []
    for vec in kern:
        at_least_one_nonzero = False
        for ind in indices:
            if vec[ind] != 0:
                at_least_one_nonzero = True
        if at_least_one_nonzero:
            new_kern.append(vec)
    return new_kern


# removes all kernel vectors that do not contribute to solution
def remove_kern_unnecessary_vecs(bv_indices, shared_indices_not_bv, kern):
    new_kern = []
    kern_remainder = []
    for vec in kern:
        allzero = True
        for ind in bv_indices:
            if vec[ind] != 0:
                allzero = False
        if allzero:
            kern_remainder.append(vec)

    kern_vecs_removed = []
    for ind in shared_indices_not_bv:
        non_zeros = []
        ctr = 0
        for vec in kern:
            if vec in kern_remainder and vec[ind] != 0:
                non_zeros.append(ctr)
            ctr += 1
        if len(non_zeros) == 1:
            if not non_zeros[0] in kern_vecs_removed:
                kern_vecs_removed.append(non_zeros[0])

    ctr = 0
    for vec in kern:
        if not ctr in kern_vecs_removed:
            new_kern.append(vec)
        ctr += 1
    return new_kern


# checks whether the scheme is secure against collusion
def verify_collusion_security_generalized(
    blindingvalue,
    kenc,
    cenc,
    benc,
    unknown,
    kern,
    uvector,
    target_vector,
    list_bv_indices,
) -> bool:
    (lis_masterkeys, lis_vars_kenc, lis_vars_cenc, lis_vars_benc) = obtain_masterkeys(
        blindingvalue, kenc, cenc, benc, unknown
    )

    collusion_msg = []
    collusion_secure = False

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

    kern = reduce_kern(lis_shared_indices, kern)

    kern = remove_kern_unnecessary_vecs(
        list_bv_indices, lis_shared_indices_not_bv, kern
    )

    transcript_found, transcript_msg = (
        print_transcript_to_trivial_and_collusion_security(
            kern, uvector, target_vector, list_bv_indices, lis_shared_indices_not_bv
        )
    )
    collusion_msg.append(transcript_msg)

    if transcript_found:
        collusion_secure = True

    if not transcript_found:
        # print("\n\t If there exists a solution for the previous system of equations such that the following system of equations holds:")
        collusion_msg.append(
            "\n\t If there exists a solution for the previous system of equations such that the following system of equations holds:"
        )

        msg = ""
        ctr = 1
        for ind in lis_shared_indices_not_bv:
            msg2 = "\n\t\t (" + str(ctr + len(list_bv_indices) + 1) + ") "
            first = True
            at_least_one_nonzero = False
            for ind2 in range(len(kern)):
                eq_is_zero = False
                el = cancel(kern[ind2][ind])
                if not el.is_integer:
                    eq = "(" + str(el) + ")"
                    at_least_one_nonzero = True
                else:
                    if el != 0:
                        eq = str(kern[ind2][ind])
                        at_least_one_nonzero = True
                    else:
                        eq_is_zero = True

                if not eq_is_zero:
                    if not first:
                        msg2 += " + c" + str(ind2) + "*" + eq
                    else:
                        msg2 += " c" + str(ind2) + "*" + eq
                        first = False
            if at_least_one_nonzero:
                msg2 += " = 0,"
                msg += msg2
                ctr += 1
        # print(msg)
        collusion_msg.append(msg)
        # print("\n\t then the scheme is secure against collusion. If not, then the scheme may be vulnerable to a collusion attack.")
        collusion_msg.append(
            "\n\t then the scheme is secure against collusion. If not, then the scheme may be vulnerable to a collusion attack."
        )

        collusion_secure = False

    return collusion_secure, "\n".join(collusion_msg)


# generates and prints a transcript that proves trivial and collusion security of the scheme
def print_transcript_to_trivial_and_collusion_security(
    kern, uvector, target_vector, list_bv_indices, lis_shared_indices_not_bv
):

    msg_output = []

    # print("\n\t Attempting to compute transcript to trivial and collusion security..")
    msg_output.append(
        "\n\t Attempting to compute transcript to trivial and collusion security.."
    )

    kern_short = []
    for vec in kern:
        vec_s = []
        for ind in lis_shared_indices_not_bv:
            vec_s.append(vec[ind])
        kern_short.append(vec_s)

    mat_kern_short = Matrix([Matrix(vec).transpose() for vec in kern_short])
    mks_ns = mat_kern_short.transpose().nullspace()

    if len(mks_ns) == 0:
        # print("\n\t The system could not find a transcript.")
        msg_output.append("\n\t The system could not find a transcript.")

        return False, "\n".join(msg_output)

    kern_red = []
    for ks_vec in mks_ns:
        vec = cancel(ks_vec[0] * kern[0])
        for ind in range(1, len(ks_vec)):
            vec += cancel(ks_vec[ind] * kern[ind])
        kern_red.append(vec)

    kern_red2 = []
    for vec in kern_red:
        if sum(target_vector[i] * vec[i] for i in range(len(target_vector))) != 0:
            kern_red2.append(vec)

    if len(kern_red2) == 0:
        # print("\n\t The system could not find a transcript.")
        msg_output.append("\n\t The system could not find a transcript.")
        return False, "\n".join(msg_output)

    kern_vec = cancel(kern_red2[0])
    for vec in kern_red2[1:]:
        kern_vec += vec

    # print("\n\t The system found a transcript, so the scheme is trivially secure and secure against collusion.")
    msg_output.append(
        "\n\t The system found a transcript, so the scheme is trivially secure and secure against collusion."
    )

    # print("\t Substitutions for the terms associated with the blinding value:")
    msg_output.append(
        "\t Substitutions for the terms associated with the blinding value:"
    )

    for ind in list_bv_indices:
        # print("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))
        msg_output.append("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))

    # print("\n\t Substitutions for the special terms that are shared among keys and are not associated with the blinding value:")
    msg_output.append(
        "\n\t Substitutions for the special terms that are shared among keys and are not associated with the blinding value:"
    )

    for ind in lis_shared_indices_not_bv:
        # print("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))
        msg_output.append("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))

    lis_rest_indices = [
        ind
        for ind in range(len(uvector))
        if not ind in list_bv_indices and not ind in lis_shared_indices_not_bv
    ]
    # print("\n\t Substitutions for the rest of the terms:")
    msg_output.append("\n\t Substitutions for the rest of the terms:")

    for ind in lis_rest_indices:
        # print("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))
        msg_output.append("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))

    return True, "\n".join(msg_output)


# analyzes the trivial and collusion security of the scheme
def analysis_trivial_and_collusion_security(blindingvalue, kenc, cenc, benc, unknown):

    msg_output = []

    # pprint("\t\tMPK encodings: \t\t\t" + str(benc) + "\n", use_unicode=True)
    msg_output.append("\t\tMPK encodings: \t\t\t" + str(benc) + "\n")
    # pprint("\t\tKey encodings: \t\t\t" + str(kenc) + "\n", use_unicode=True)
    msg_output.append("\t\tKey encodings: \t\t\t" + str(kenc) + "\n")
    # pprint("\t\tCiphertext encodings: \t" + str(cenc) + "\n", use_unicode=True)
    msg_output.append("\t\tCiphertext encodings: \t" + str(cenc) + "\n")

    trivial_secure = False
    collusion_secure = False

    # print("\n == Performing simple trivial security check.. ==")
    msg_output.append("\n == Performing simple trivial security check.. ==")

    (
        trivial_secure,
        kern,
        uvector,
        target_vector,
        list_bv_indices,
        trivial_output_s,
    ) = verify_trivial_security_generalized(blindingvalue, kenc, cenc, benc, unknown)
    msg_output.append(trivial_output_s)

    if trivial_secure:
        # print("\n\t The scheme is probably trivially secure, because there exists a solution for the equations.")
        msg_output.append(
            "\n\t The scheme is probably trivially secure, because there exists a solution for the equations."
        )
    else:
        # print("\n\t The scheme may not be trivially secure, because no solution could be found.")
        msg_output.append(
            "\n\t The scheme may not be trivially secure, because no solution could be found."
        )

    # print("\n == Performing collusion security check.. ==")
    if kern != None:
        msg_output.append("\n == Performing collusion security check.. ==")

        collusion_secure, collusion_output_s = verify_collusion_security_generalized(
            blindingvalue,
            kenc,
            cenc,
            benc,
            unknown,
            kern,
            uvector,
            target_vector,
            list_bv_indices,
        )
        msg_output.append(collusion_output_s)
    else:
        msg_output.append("\n == Could not perform the collusion security check.. ==")
        collusion_secure = False

    return trivial_secure, collusion_secure, "\n".join(msg_output)


if __name__ == "__main__":

    # BSW07

    alpha, b, bp, b0, b1, r, rp, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, x, y, s, sp"
    )

    # actual encoding
    k1 = (alpha + r) / b
    k2 = r + rp * b0
    k3 = rp
    c1 = s * b
    c2 = s
    c3 = s * b1
    mpk1 = b
    mpk2 = b0
    mpk3 = b1
    mpk4 = 1

    # no known values

    unknown = [alpha, b, b0, b1, r, rp, s]

    k = [k1, k2, k3]
    c = [c1, c2, c3]
    mpk = [mpk1, mpk2, mpk3, mpk4]
    gp = []

    # verify_trivial_security_generalized(alpha*s, k, c, mpk, unknown)

    analysis_trivial_and_collusion_security(alpha * s, k, c, mpk, unknown)

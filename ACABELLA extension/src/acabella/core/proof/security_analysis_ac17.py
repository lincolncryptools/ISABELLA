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
from acabella.core.proof.ac17_correctness_checks import *
from acabella.core.common.encodings import *
from acabella.core.proof.trivial_security_and_collusion import *
from acabella.core.proof.security_proof import *
from acabella.core.proof.FABEO_properties import *

init_printing(use_unicode=True)


def security_analysis(
    masterkey, special_s, kenc, cenc, benc, unknown, controlled, constraints
):
    """
    This is the main function that performs all steps relevant to the security analysis of a scheme satisfying the AC17 form

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        controlled (bool): Flag
        constraints (list): List of constraints.

    Returns:
        (bool): The scheme is trivial secure.
        (bool): The scheme is collusion secure.
        (str): Process log.
    """

    analysis_log = []
    proof_log = []

    (correct, kenc, cenc, ac17_log) = correct_form(kenc, cenc, benc, unknown)
    analysis_log.append(ac17_log)

    if not correct:
        # print("\n Security analysis for AC17 schemes cannot be performed.")
        analysis_log.append(
            "\n Security analysis for AC17 schemes cannot be performed."
        )
    else:
        # print("\n Performing security analysis on the following encodings:\n")
        analysis_log.append(
            "\n Performing security analysis on the following encodings:\n"
        )
        # pprint("\t\tMPK encodings: \t\t\t" + str(benc) + "\n", use_unicode=True)
        analysis_log.append("\t\tMPK encodings: \t\t\t" + str(benc) + "\n")
        # pprint("\t\tKey encodings: \t\t\t" + str(kenc) + "\n", use_unicode=True)
        analysis_log.append("\t\tKey encodings: \t\t\t" + str(kenc) + "\n")
        # pprint("\t\tCiphertext encodings: \t" + str(cenc) + "\n", use_unicode=True)
        analysis_log.append("\t\tCiphertext encodings: \t" + str(cenc) + "\n")

        # print("\n == Performing simple trivial security check.. ==")
        analysis_log.append("\n == Performing simple trivial security check.. ==")
        trivial_secure, log_trivial_security = verify_trivial_security(
            masterkey, special_s, kenc, cenc, benc, unknown, controlled, constraints
        )
        analysis_log.append(log_trivial_security)

        # print("\n == Performing collusion security checks.. ==")
        analysis_log.append("\n == Performing collusion security checks.. ==")
        collusion_secure, log = generate_the_proofs_and_check_collusion(
            masterkey, special_s, kenc, cenc, benc, unknown
        )
        analysis_log.append(log)

        log = FABEO_properties(masterkey, special_s, kenc, cenc, benc, unknown)
        analysis_log.append(log)

        if trivial_secure and collusion_secure:
            proof_log = generate_the_proofs(
                masterkey, special_s, kenc, cenc, benc, unknown
            )

        return (trivial_secure, collusion_secure, "\n".join(analysis_log), proof_log)


def security_analysis_ven23(
    masterkey, special_s, kenc, cenc, benc, unknown, controlled, constraints
):
    """
    This is the main function that performs all steps relevant to the security analysis of a scheme satisfying the AC17 form

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        controlled (bool): Flag
        constraints (list): List of constraints.

    Returns:
        (bool): The scheme is trivial secure.
        (bool): The scheme is collusion secure.
        (str): Process log.
    """

    print("security analysis ven23 STARTS HERE")

    analysis_log = []
    proof_log = []

    # TODO: trivial security, collusion security, FABEO for GPES

    proof_log = generate_the_proofs_ven23(
        masterkey, special_s, kenc, cenc, benc, unknown
    )

    # return (trivial_secure, collusion_secure, '\n'.join(analysis_log), proof_log)
    return (True, True, "\n".join(analysis_log), proof_log)


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

    # generate_the_encodings_then_the_proofs(alpha, s, mpk, k_fixed, k_att, c_fixed, c_att, unknown, ["sp"], 1)

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

    # generate_the_proofs(alpha, s, k, c, mpk, unknown)
    security_analysis(alpha, s, k, c, mpk, unknown, [], [])

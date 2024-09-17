from sympy import symbols, init_printing

from acabella.core.cryptanalysis.decryption import DecryptionAttack
from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_bsw07_cpabe():

    # BSW07

    alpha, b, bp, b0, b1, r, rp, r0, r1, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r0, r1, x, y, s, sp"
    )
    A11, A12, A21, A22, w2, w2p = symbols("A11, A12, A21, A22, w2, w2p")

    # actual encoding
    k1 = (alpha + r) / b
    k2 = r + r0 * b0
    k3 = r0
    k4 = (alpha + rp) / b
    k5 = rp + r1 * b1
    k6 = r1
    c1 = s * b
    c2 = A11 * s + A22 * sp
    c3 = (A11 * s + A12 * sp) * b0
    c4 = (A21 * s + A22 * sp) * b1
    c5 = A21 * s + A22 * sp
    mpk1 = b
    mpk2 = b0
    mpk3 = b1
    mpk4 = 1

    # no known values

    unknown = [alpha, b, b0, b1, r, rp, r0, r1, s, sp]

    k = [k1, k2, k3, k4, k5, k6]
    c = [c1, c2, c3, c4, c5]
    mpk = [mpk1, mpk2, mpk3, mpk4]
    gp = []

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, [k1, k2, k3], c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())

    # trivial_secure, collusion_secure, details = analysis_trivial_and_collusion_security(alpha * s, [k1, k2, k3], c, mpk, unknown)
    # print(details)

    # """
    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha * s, k, c, mpk, gp, unknown)
    decryption_attack.run()
    msg = decryption_attack.show_solution()
    print(msg)
    # """

    """
    # all_v = gen_all_p_ex_dict(k, c, mpk, gp)

    # for elem in all_v:
    #     elem["op"] = expand(cancel(elem["op"]))

    # msg = decryption_attack_super_matrix_generalized(alpha * s, all_v, [alpha, r, s, b, bp])
    # print(msg)

    # p = gen_all_p(k, c, mpk)
    # (result, m1, m2, f_sol) = decryption_attack_generalized_alt(alpha * s, p, unknown)
    # if result:
    #     print("\n\t[*] Attack found: \n", m2, f_sol)
    # if not result:
    #     print("\n\t[*] No attack found.\n")
    
    # equivalent encoding without denominators
    k1 = alpha + r
    k2 = r*b + rp*b0
    k3 = rp
    c1 = s*b
    c2 = s
    c3 = s*b1
    mpk1 = b
    mpk2 = b0
    mpk3 = b1
    mpk4 = 1
    
    # no known values

    unknown = [alpha, b, b0, b1, r, rp, s]

    k = [k1, k2, k3]
    c = [c1, c2, c3]
    mpk = [mpk1, mpk2, mpk3, mpk4]
    
    # p = gen_all_p(k, c, mpk)
    # (result, m1, m2, f_sol) = decryption_attack_generalized_alt(alpha * s, p, unknown)
    # if not result:
    #     print("\n\t[*] No attack found.\n")

    security_analysis(alpha*b, s, k, c, mpk, unknown, [], [])
    """

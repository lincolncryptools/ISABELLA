from sympy import symbols, init_printing

from acabella.core.cryptanalysis.decryption import DecryptionAttack
from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_abgw17_cpabe():

    # ABGW17 - CP-ABE scheme

    alpha, b, bp, b0, b1, r, rp, r0, r1, x1, x2, y, s, s1, s2, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r0, r1, x1, x2, y, s, s1, s2, sp"
    )
    A11, A12, A21, A22, w2, w2p = symbols("A11, A12, A21, A22, w2, w2p")

    k1 = alpha + r * b
    k2 = r
    k3 = r * bp / (b0 + y * b1)
    k4 = r * bp / (b0 + x1 * b1)
    k1p = alpha + rp * b
    k2p = rp
    k3p = rp * bp / (b0 + y * b1)
    k4p = rp * bp / (b0 + x2 * b1)
    c1 = A11 * s + A12 * sp
    c2 = A21 * s + A22 * sp
    c3 = s1 * bp + (A11 * s + A12 * sp) * b
    c4 = s1 * (b0 + x1 * b1)
    c5 = s2 * bp + (A21 * s + A22 * sp) * b
    c6 = s2 * (b0 + x2 * b1)
    mpk1 = b
    mpk2 = b0
    mpk3 = b1
    mpk4 = bp

    # no known values

    unknown = [alpha, b, bp, b0, b1, r, rp, r0, r1, s, sp, s1, s2]

    # kenc1 and cenc1 are in the single-user setting
    kenc1 = [k1, k2, k3, k4]
    cenc1 = [c1, c3, c4]
    # kenc2 and cenc2 are in the two-user setting
    kenc2 = [k1, k2, k3, k4, k1p, k2p, k3p, k4p]  # , k1p, k2p, k4p
    cenc2 = [c1, c3, c4, c2, c5, c6]  # c1, c2, c3, c4, c5, c6
    mpk = [mpk1, mpk2, mpk3, mpk4, 1]
    gp = []

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, kenc1, cenc1, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())

    # for the attack, we need a concrete policy
    lis_subs = [(A11, 1), (A12, 1), (A21, 0), (A22, -1)]

    ctr = 0
    for cpoly in cenc2:
        cenc2[ctr] = cenc2[ctr].subs(lis_subs)
        ctr += 1

    # """
    print("\n Decryption attack: \n")
    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha * s, kenc2, cenc2, mpk, gp, unknown)
    decryption_attack.run()
    msg = decryption_attack.show_solution()
    print(msg)
    # """

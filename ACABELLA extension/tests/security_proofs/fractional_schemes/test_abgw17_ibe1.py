from sympy import symbols, init_printing

from acabella.core.cryptanalysis.decryption import DecryptionAttack
from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_abgw17_ibe1():

    # ABGW17 - IBE1 scheme

    alpha, b, bp, b0, b1, r, rp, r0, r1, x, x1, x2, y, s, s1, s2, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r0, r1, x, x1, x2, y, s, s1, s2, sp"
    )

    k1 = alpha / (b + x1)
    k2 = alpha / (b + x2)
    c1 = s * (b + y)
    mpk1 = b

    # no known values

    unknown = [alpha, b, s]

    k = [k1]
    c = [c1]
    mpk = [mpk1]
    gp = []

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())

    """
    ctr = 0
    for kpoly in k:
        k[ctr] = k[ctr].subs(A11,-w2*A12)
        ctr += 1
    
    ctr = 0
    for kpoly in kp:
        kp[ctr] = kp[ctr].subs(A21, -w2p*A22)
        ctr += 1

    # print(kp)
    """

    # """
    print("\n Decryption attack: \n")
    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha * s, k, c, mpk, gp, unknown)
    decryption_attack.run()
    msg = decryption_attack.show_solution()
    print(msg)
    # """

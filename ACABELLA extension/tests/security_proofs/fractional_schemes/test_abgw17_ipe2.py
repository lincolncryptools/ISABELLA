from sympy import symbols, init_printing

from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_abgw17_ipe2():

    # ABGW17 - IPE2 scheme

    alpha, b, bp, b0, b1, b2, r, rp, r0, r1, x, x1, x2, y, z, s, s1, s2, sp = symbols(
        "alpha, b, bp, b0, b1, b2, r, rp, r0, r1, x, x1, x2, y, z, s, s1, s2, sp"
    )

    y1, y2 = symbols("y1, y2")

    k1 = alpha / (x1 * b1 + x2 * b2)
    c1 = s * (y1 + b1)
    c2 = s * (y2 + b2)
    mpk1 = b1
    mpk2 = b2

    # no known values

    unknown = [alpha, b1, b2, s]

    k = [k1]
    c = [c1, c2]
    mpk = [mpk1, mpk2]
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

    """    
    print("\n Decryption attack: \n")
    decryption_attack = DecryptionAttack()                                       
    decryption_attack.init(alpha * s, k, c, mpk, gp, unknown)                      
    decryption_attack.run()                                                      
    msg = decryption_attack.show_solution()         
    print(msg)
    """

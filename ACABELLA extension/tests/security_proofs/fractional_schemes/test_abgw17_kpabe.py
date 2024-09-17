from sympy import symbols, init_printing

from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_abgw17_kpabe():

    # ABGW17 - KP-ABE scheme

    alpha, b, bp, b0, b1, r, rp, r0, r1, x1, x2, y, s, s1, s2, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r0, r1, x1, x2, y, s, s1, s2, sp"
    )
    r2, r2p = symbols("r2, r2p")
    A11, A12, A13, A21, A22, A23, A31, A32, A33 = symbols(
        "A11, A12, A13, A21, A22, A23, A31, A32, A33"
    )
    A11p, A12p, A13p, A21p, A22p, A23p, A31p, A32p, A33p = symbols(
        "A11p, A12p, A13p, A21p, A22p, A23p, A31p, A32p, A33p"
    )

    """
    A11 = 1
    A12 = 1
    A13 = 0
    A21 = 0
    A22 = 0
    A23 = 0
    
    A11p = 0
    A12p = 0
    A13p = 0
    A21p = 0
    A22p = 0
    A23p = 0
    # x2 = y - x1
    """

    k1 = (A11 * alpha + A12 * r + A13 * r2) / (b0 + y * b1)
    k2 = (A21 * alpha + A22 * r + A23 * r2) / (b0 + x2 * b1)
    k4 = A11 * alpha + A12 * r + A13 * r2
    k5 = A21 * alpha + A22 * r + A23 * r2
    k1p = (A11p * alpha + A12p * rp + A13p * r2p) / (b0 + x1 * b1)
    k2p = (A21p * alpha + A22p * rp + A23p * r2p) / (b0 + x2 * b1)
    k4p = A11p * alpha + A12p * rp + A13p * r2p
    k5p = A21p * alpha + A22p * rp + A23p * r2p
    c1 = s - s1
    c2 = s1 * (b0 + y * b1)
    c3 = s - s2
    c4 = s2 * (b0 + y * b1)
    mpk1 = b
    mpk2 = b0
    mpk3 = b1

    # no known values

    unknown = [alpha, b, bp, b0, b1, r, rp, r0, r1, r2, s, sp, s1, s2]

    k = [k2, k5]  # , k1p, k2p, k4p, k5p] # k1p, k2p, k3p, k4p, k5p, k6p
    c = [c1, c2]
    mpk = [mpk2, mpk3, 1]
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

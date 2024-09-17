from sympy import symbols, init_printing

from acabella.core.cryptanalysis.decryption import DecryptionAttack
from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_ksw08_ipe():

    # KSW08 IPE

    alpha, b, bp, b0, b1, b2, r, rp, s = symbols("alpha, b, bp, b0, b1, b2, r, rp, s")

    x0, x1, x2, y0, y1, y2, y0p, y1p, y2p, z = symbols(
        "x0, x1, x2, y0, y1, y2, y0p, y1p, y2p, z", rational=True
    )

    nz = symbols("nz", is_zero=False)

    # """
    # (x0, x1, x2) = (1,1,1)
    # (y0, y1) = (1,1)
    # z = 1
    # y2 = (-x0*y0 - x1*y1 + z + nz)/x2
    # (y0p, y1p, y2p) = (0,0,0)
    # y2p = (-x0*y0p - x1*y1p + z + nz)/x2
    # """

    # print(cancel(x0*y0 + x1*y1 + x2*y2), z)

    k1 = alpha + r * (z * b + y0 * b0 + y1 * b1 + y2 * b2)
    k2 = r
    k3 = alpha + rp * (z * b + y0p * b0 + y1p * b1 + y2p * b2)
    k4 = rp
    c1 = s * (b * x0 + b0)
    c2 = s * (b * x1 + b1)
    c3 = s * (b * x2 + b2)
    c4 = s
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = b2

    # known values: x0, x1, y0, y1, y0p, y1p

    unknown = [alpha, b, b0, b1, b2, r, rp, s]

    # k = [k1, k2, k3, k4]
    k = [k1, k2]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk4]

    # k_combs = [cancel(s*k_poly) for k_poly in [k1, k3]]
    # c_combs = [cancel(r*c_poly) for c_poly in [c1, c2, c3]] + [cancel(rp*c_poly) for c_poly in [c1, c2, c3]]

    """
    decryption_attack = DecryptionAttack()                                       
    decryption_attack.init(alpha * s, k, c, mpk, [], unknown)                      
    decryption_attack.run()                                                      
    msg = decryption_attack.show_solution()
    print(msg)
    """

    # check_kernel_products(k_combs, c_combs, mpk, unknown)

    # generate_the_proofs(alpha, s, k, c, mpk, unknown)

    # print("The attack is: \n")

    # security_analysis(alpha, s, k, c, mpk, unknown, [], [])

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

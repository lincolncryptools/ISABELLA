from sympy import symbols, init_printing

from acabella.core.cryptanalysis.decryption import DecryptionAttack
from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_rw13_cpabe():

    # RW13

    alpha, b, bp, b0, b1, r, rp, rp2, x, y, z, s, sp, sp2, v2 = symbols(
        "alpha, b, bp, b0, b1, r, rp, rp2, x, y, z, s, sp, sp2, v2"
    )

    k1 = alpha + r * b
    k2 = r * bp + rp * (b0 + y * b1)
    k3 = r
    k4 = rp
    k5 = r * bp + rp2 * (b0 + z * b1)
    k6 = rp2
    c1 = (s - v2) * b + sp * bp
    c2 = sp * (b0 + x * b1)
    c3 = s
    c4 = sp
    c5 = v2 * b + sp2 * bp
    c6 = sp2 * (b0 + z * b1)
    c7 = sp2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = bp

    # known values: x, y

    unknown = [alpha, b, b0, b1, bp, r, rp, rp2, s, sp, sp2, v2]

    k = [k1, k2, k3, k4, k5, k6]
    c = [c1, c2, c3, c4, c5, c6, c7]
    mpk = [mpk1, mpk2, mpk3, mpk4]

    # check_kernel_products(k, c, mpk, unknown)

    # security_analysis(alpha, s, k, c, mpk, unknown, [], [])

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

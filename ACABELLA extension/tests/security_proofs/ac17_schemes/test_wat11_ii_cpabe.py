from sympy import symbols, init_printing, parse_expr

from acabella.core.cryptanalysis.decryption import DecryptionAttack
from acabella.core.proof.security import SecurityAttack
from acabella.core.proof.security_proof import (
    generate_the_encodings_then_the_proofs,
    get_indexed_encoding,
)

init_printing(use_unicode=True)


def test_wat11_ii_cpabe():

    # Wat11-II

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

    # check_kernel_products(k, c, mpk, unknown)

    # security_analysis(alpha, s, k, c, mpk, unknown, [], [])

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

    # Wat11 with indexed encodings

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

    generate_the_encodings_then_the_proofs(
        alpha, s, mpk, k_fixed, k_att, c_fixed, c_att, unknown, ["sp"], 1
    )

    # Wat11 with more general matrices

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2 = symbols(
        "alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2"
    )
    A11, A12, A21, A22, w2 = symbols("A11, A12, A21, A22, w2")

    A21 = -A22 * w2

    k1 = alpha + r * b
    k2 = r * b0
    k3 = r
    k4 = r * b1
    c1 = A11 * s * b + A12 * s1 * b + sp * b1
    c2 = s
    c3 = sp
    c4 = A21 * s * b + A22 * s1 * b + sp * b2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = 1
    mpk5 = b2

    unknown = [alpha, b, b0, b1, b2, r, s, s1, sp]

    k = [k1, k2, k3, k4]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk5]

    k_combs = [s * k_poly for k_poly in [k1, k2, k4]] + [
        sp * k_poly for k_poly in [k1, k2, k4]
    ]
    c_combs = [r * c_poly for c_poly in [c1, c4]]
    # check_kernel_products(k_combs, c_combs, mpk, unknown)

    # security_analysis(alpha, s, k, c, mpk, unknown, [], [])

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

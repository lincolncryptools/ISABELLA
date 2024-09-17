from sympy import symbols

from acabella.core.cryptanalysis.conditional import ConditionalDecryptionAttack
from acabella.core.proof.security_analysis_ac17 import parse_expr, get_indexed_encoding
from acabella.core.proof.security import SecurityAttack


def test_jlww13():

    # JLWW13

    alpha, b, bp, b0, b1, r, rp, r1, r2, r3, r1p, r2p, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r1, r2, r3, r1p, r2p, x, y, s, sp"
    )

    A11, A12, A21, A22, w2 = symbols("A11, A12, A21, A22, w2")

    A11 = -A12 * w2
    A21 = -A22 * w2

    k1 = alpha + r1
    k2 = r1 + r2 * b0
    k3 = r1 + r3 * b1
    k4 = r2
    k5 = r3
    # k4 = alpha + r1p
    # k5 = r1p + r2p*b1
    # k6 = r2p
    c1 = (A11 * s + A12 * sp) * b0
    c2 = (A21 * s + A22 * sp) * b1
    # c3 = s-sp
    c3 = s
    c4 = sp
    mpk1 = b0
    mpk2 = b1

    # known values: x, y

    unknown = [alpha, b0, b1, r1, r2, r3, r1p, r2p, s, sp]

    k = [k1, k2, k3, k4, k5]  # k4, k5, k6
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2]

    # all_v = DecryptionAttack.gen_all_p_ex_dict(k, c, mpk, [])

    # decryption_attack = DecryptionAttack()
    # decryption_attack.init(alpha * s, all_v, unknown)
    # decryption_attack.run()
    # msg = decryption_attack.show_solution()
    # print(msg)

    """
    k_combs = [s*k_poly for k_poly in [k1, k2, k3]] + [sp*k_poly for k_poly in [k1, k2]]
    c_combs = [r2*c_poly for c_poly in [c1, c2]]
    
    check_kernel_products(k_combs, c_combs, mpk, unknown)
    
    generate_the_proofs_and_check_collusion(alpha, s, k, c, mpk, unknown)
    """

    # security_analysis(alpha, s, k, c, mpk, unknown, [], [])

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

    # (mat_k1, uvector1) = writeencodingasprod([k1, k2, k3], unknown)
    # (mat_k2, uvector2) = writeencodingasprod([k4, k5, k6], unknown)
    # print(mat_k1, uvector1)
    # print("\n", mat_k2, uvector2)

    # (mat_k3, uvector3) = writeencodingasprod(k, unknown)
    # print("\n\n", mat_k3, uvector3, Matrix(mat_k3).rank())

    #### using the encodings helper
    alpha, b, bp, b0, b1, r, rp, r1, r2, r1p, r2p, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r1, r2, r1p, r2p, x, y, s, sp"
    )

    # these are fixed in the system
    att_mpk_group = parse_expr("att_mpk_group")
    att_scalar = parse_expr("att_scalar")
    policy_share = parse_expr("lambda_policy_share")

    k_fixed_1 = alpha + r
    k_att_1 = r + get_indexed_encoding("rp", 1) * att_mpk_group
    k_att_2 = get_indexed_encoding("rp", 1)
    c_att_1 = policy_share * att_mpk_group
    c_att_2 = policy_share
    mpk1 = att_mpk_group
    special_s = s

    k_fixed = [k_fixed_1]
    k_att = [k_att_1, k_att_2]
    c_fixed = []
    c_att = [c_att_1, c_att_2]
    mpk = []

    prefixes = ["rp"]
    nr_indexed_encodings = 1

    cd_attack = ConditionalDecryptionAttack()
    cd_attack.init(
        alpha,
        special_s,
        mpk,
        k_fixed,
        k_att,
        c_fixed,
        c_att,
        [alpha, r, s],
        prefixes,
        nr_indexed_encodings,
    )
    cd_attack.run()
    result = cd_attack.show_solution()
    print(result)

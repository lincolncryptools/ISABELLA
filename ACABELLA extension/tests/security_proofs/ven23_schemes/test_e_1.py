from sympy import symbols

from acabella.core.proof.security import SecurityAttackVen23
from acabella.core.extensions.ven23 import validate_cm


def test_e_1():

    # Decentralized LU CP-ABE from FDH (based on RW15)
    # Scheme E.1 from https://eprint.iacr.org/2023/143.pdf
    # Two (decentralized) authorities, n_alpha = n_aut = 2
    # One user, with GID

    # encoding correspondences
    # b' -> bp
    # s' -> sp
    # s_j -> s e.g. s1, s2, etc.
    # c'j -> cp_j

    # policy
    # attr1 AND attr 2
    # A = [A11, A12]
    #     [A21, A22]

    # attr1 is managed by authority 1 and attr2 belongs to authority 2

    # FDHs
    # FDH(b_attr) = 1
    # FDH(r_GID) = 2

    n_alpha = n_aut = 2

    # symbol definition

    alpha_1, alpha_2 = symbols("alpha_1, alpha_2")
    b1, bp1 = symbols("b1, bp1")
    b2, bp2 = symbols("b2, bp2")

    b_attr_1, b_attr_2 = symbols("b_attr_1, b_attr_2")
    r_GID, r1, r2, s_tilde = symbols("r_GID, r1, r2,  s_tilde")

    s1, s2 = symbols("s1, s2")
    sp1, sp2 = symbols("sp1, sp2")
    vp1, vp2 = symbols("vp1, vp2")
    v1, v2 = symbols("v1, v2")

    A11, A12, A21, A22 = symbols("A11, A12, A21, A22")

    # validate_cm, E.1

    # MPK encodings

    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    # key encodings

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    kenc = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    # ciphertext encodings

    CM = [s_tilde]

    mu_1 = A12 * vp1
    mu_2 = A22 * vp2

    c_1_1 = mu_1 + s1 * b1
    c_1_2 = mu_2 + s2 * b2
    c_2_1 = s1 * bp1 + sp1 * b_attr_1
    c_2_2 = s2 * bp2 + sp2 * b_attr_2

    lambda_1 = A11 * s_tilde + A12 * v1
    lambda_2 = A21 * s_tilde + A22 * v2

    cp_1 = lambda_1 + alpha_1 * s1
    cp_2 = lambda_2 + alpha_2 * s2

    cenc = [c_1_1, c_1_2, c_2_1, c_2_2, cp_1, cp_2]

    unknown = [
        alpha_1,
        alpha_2,
        b1,
        bp1,
        b2,
        bp2,
        b_attr_1,
        b_attr_2,
        s1,
        s2,
        sp1,
        sp2,
        vp1,
        vp2,
        r1,
        r2,
    ]

    res, msg = validate_cm(
        [c_1_1, c_1_2, c_2_1, c_2_2],
        [cp_1, cp_2],
        CM,
        kenc,
        [alpha_1, alpha_2],
        mpk,
        [r_GID],
    )
    assert res, "The scheme is not GPES"

    """
    FDH definitions
    F(b_att) = 1
    F(r_GID) = 2

    GID
    user global id x
    """

    FDH_entry_1 = {"symbols": [b_attr_1, b_attr_2], "id": 1}
    FDH_entry_2 = {"symbols": [r_GID], "id": 2}

    FDH_corr = [FDH_entry_1, FDH_entry_2]

    # Sym-Prop-G

    # we start with a single authority and alpha_1

    mpk = [b1, bp1, b_attr_1]

    # key encodings

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k2_attr_1 = r1 * b_attr_1
    kenc = [k_1_1, k2_attr_1]

    # ciphertext encodings

    CM = [s_tilde]

    mu_1 = A12 * vp1
    c_1_1 = mu_1 + s1 * b1
    c_2_1 = s1 * bp1 + sp1 * b_attr_1

    lambda_1 = A11 * s_tilde + A12 * v1
    cp_1 = lambda_1 + alpha_1 * s1

    cenc = [c_1_1, c_2_1, cp_1]

    unknown = [alpha_1, b1, bp1, b_attr_1, s1, sp1, vp1, r1]

    res, msg = validate_cm([c_1_1, c_2_1], [cp_1], CM, kenc, [alpha_1], mpk, [r_GID])
    assert res, "The scheme is not GPES"

    security_attack = SecurityAttackVen23()
    security_attack.init(CM, kenc, cenc, mpk, unknown, alpha_1, s_tilde)

    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

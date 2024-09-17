from sympy import symbols
from acabella.core.extensions.ven23 import *


def test_validation_cm():

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

    CM = 3 * s_tilde + alpha_1 * s1

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

    lone_vars = [s_tilde]
    non_lone_vars = [s1, s2, sp1, sp2]
    alphas = [alpha_1, alpha_2]

    # correct CM

    CM = 3 * s_tilde + alpha_1 * s1

    # incorrect cenc

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

    # MSK

    alphas = [alpha_1, alpha_2]

    # MPK encodings

    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    # key encodings

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    k = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    # ciphertext encodings

    CM = 3 * s_tilde + alpha_1 * s1

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

    cenc = [s1, c_1_1, c_1_2, c_2_1, c_2_2, cp_1, cp_2]

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
        v1,
        v2,
        vp1,
        vp2,
    ]

    # validation

    ## 1. CM

    lone_vars = [s_tilde]
    non_lone_vars = [s1, s2, sp1, sp2]
    alphas = [alpha_1, alpha_2]

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

    # MSK

    alphas = [alpha_1, alpha_2]

    # MPK encodings

    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    # key encodings

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    k = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    # ciphertext encodings

    CM = 3 * s_tilde + alpha_1 * s1

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

    cenc = [s1 * s_tilde + s_tilde * A11, c_1_1, c_1_2, c_2_1, c_2_2, cp_1, cp_2]

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
        v1,
        v2,
        vp1,
        vp2,
    ]

    # validation

    ## 1. CM

    lone_vars = [s_tilde]
    non_lone_vars = [s1, s2, sp1, sp2]
    alphas = [alpha_1, alpha_2]

    known_vars = []

    # mini functions: validate_cm_element_a

    elem = 3 * s_tilde

    assert validate_cm_element_a(elem, lone_vars, known_vars)
    assert validate_cm_element_a(s_tilde, lone_vars, known_vars)
    assert validate_cm_element_a(s_tilde * 235, lone_vars, known_vars)
    assert not validate_cm_element_a(s_tilde * s1, lone_vars, known_vars)
    assert not validate_cm_element_a(3453, lone_vars, known_vars)
    assert not validate_cm_element_a(s_tilde + 33, lone_vars, known_vars)
    assert not validate_cm_element_a(b1, lone_vars, known_vars)
    assert not validate_cm_element_a(b1 * s_tilde, lone_vars, known_vars)
    assert not validate_cm_element_a(b1 * s1, lone_vars, known_vars)
    assert not validate_cm_element_a(s_tilde * s_tilde, lone_vars, known_vars)
    assert not validate_cm_element_a(s_tilde * s1 * 353, lone_vars, known_vars)

    # mini functions: validate_cm_element_b

    elem = 3 * s_tilde

    assert not validate_cm_element_b(elem, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(s_tilde, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(s_tilde * 235, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(s_tilde * s1, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(3453, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(s_tilde + 33, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(b1, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(b1 * s_tilde, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(b1 * s1, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(
        s_tilde * s_tilde, non_lone_vars, alphas, known_vars
    )
    assert not validate_cm_element_b(
        s_tilde * s1 * 353, non_lone_vars, alphas, known_vars
    )

    assert not validate_cm_element_b(alpha_1 * b1, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(
        alpha_2 * alpha_1, non_lone_vars, alphas, known_vars
    )
    assert not validate_cm_element_b(23 * alpha_1, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(
        23 * alpha_1 * alpha_2, non_lone_vars, alphas, known_vars
    )
    assert not validate_cm_element_b(
        alpha_1 * s_tilde, non_lone_vars, alphas, known_vars
    )

    assert validate_cm_element_b(alpha_1 * s1, non_lone_vars, alphas, known_vars)
    assert validate_cm_element_b(alpha_2 * s1 * 23, non_lone_vars, alphas, known_vars)
    assert validate_cm_element_b(23 * alpha_1 * s2, non_lone_vars, alphas, known_vars)
    assert not validate_cm_element_b(
        alpha_1 * b1 * 23, non_lone_vars, alphas, known_vars
    )

    # mini functions: validate_c_element_b

    elem = 3 * s_tilde

    assert not validate_c_element_b(elem, non_lone_vars, mpk, known_vars)
    assert not validate_c_element_b(elem, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(s_tilde, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(s_tilde * 235, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(s_tilde * s1, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(3453, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(s_tilde + 33, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(b1, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(b1 * s_tilde, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(b1 * s1, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(
        s_tilde * s_tilde, non_lone_vars, alphas, known_vars
    )
    assert not validate_c_element_b(
        s_tilde * s1 * 353, non_lone_vars, alphas, known_vars
    )

    assert not validate_c_element_b(alpha_1 * b1, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(
        alpha_2 * alpha_1, non_lone_vars, alphas, known_vars
    )
    assert not validate_c_element_b(23 * alpha_1, non_lone_vars, alphas, known_vars)
    assert not validate_c_element_b(
        23 * alpha_1 * alpha_2, non_lone_vars, alphas, known_vars
    )
    assert not validate_c_element_b(
        alpha_1 * s_tilde, non_lone_vars, alphas, known_vars
    )

    assert validate_c_element_b(s1 * b1, non_lone_vars, mpk, known_vars)
    assert not validate_c_element_b(s_tilde * b1, non_lone_vars, mpk, known_vars)
    assert validate_c_element_b(23 * s1 * b1, non_lone_vars, mpk, known_vars)
    assert not validate_c_element_b(s1 * b1 * s2, non_lone_vars, mpk, known_vars)

    # mini functions: validate_k_element_a

    elem = 3 * s_tilde

    assert not validate_k_element_a(elem, alphas, known_vars)
    assert not validate_k_element_a(elem, alphas, known_vars)
    assert not validate_k_element_a(s_tilde, alphas, known_vars)

    assert validate_k_element_a(alpha_1, alphas, known_vars)
    assert validate_k_element_a(alpha_1 * 23, alphas, known_vars)
    assert not validate_k_element_a(alpha_1 * alpha_2, alphas, known_vars)
    assert not validate_k_element_a(alpha_1 * b1, alphas, known_vars)
    assert not validate_k_element_a(s1 * b1, alphas, known_vars)

    # mini functions: validate_k_element_b

    elem = 3 * s_tilde

    r1_hat, r2_hat = symbols("r1_hat, r2_hat")

    lone_vars_k = [r1_hat, r2_hat]

    assert not validate_k_element_b(elem, lone_vars_k, known_vars)
    assert not validate_k_element_b(s_tilde, lone_vars_k, known_vars)
    assert not validate_k_element_b(alpha_1, lone_vars_k, known_vars)
    assert not validate_k_element_b(alpha_1 * 23, lone_vars_k, known_vars)
    assert not validate_k_element_b(alpha_1 * alpha_2, lone_vars_k, known_vars)
    assert not validate_k_element_b(alpha_1 * b1, lone_vars_k, known_vars)
    assert not validate_k_element_b(s1 * b1, lone_vars_k, known_vars)

    assert validate_k_element_b(r1_hat, lone_vars_k, known_vars)
    assert validate_k_element_b(r2_hat, lone_vars_k, known_vars)
    assert validate_k_element_b(r2_hat * 23, lone_vars_k, known_vars)
    assert validate_k_element_b(r1_hat * 23, lone_vars_k, known_vars)

    assert not validate_k_element_b(r1_hat * 23 * r2_hat * b1, lone_vars_k, known_vars)

    # is_integer_or_known_variable

    x1, x2 = symbols("x1, x2")
    known_vars = [x1, x2]

    assert is_integer_or_known_variable(345, known_vars)
    assert is_integer_or_known_variable(x2, known_vars)
    assert is_integer_or_known_variable(x1, known_vars)
    assert not is_integer_or_known_variable(s1, known_vars)

    # validate_k_encoding_format

    alphas = [alpha_1, alpha_2]

    # MPK encodings

    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    # key encodings

    # ciphertext encodings

    CM = 3 * s_tilde + alpha_1 * s1

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

    cenc = [s1 * s_tilde + s_tilde * A11, c_1_1, c_1_2, c_2_1, c_2_2, cp_1, cp_2]

    # validation

    c_lone_vars = [s_tilde, v1, v2, vp1, vp2]
    c_non_lone_vars = [s1, s2, sp1, sp2]

    mpk_alpha = [alpha_1, alpha_2]
    mpk_b = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]
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
        v1,
        v2,
        vp1,
        vp2,
    ]

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    kenc = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    k_lone_vars = []
    k_non_lone_vars = [r1, r2, r_GID]
    known_vars = []

    assert validate_k_encoding_format(
        kenc, mpk_alpha, known_vars, k_lone_vars, k_non_lone_vars, mpk_b
    )
    assert not validate_k_encoding_format(
        kenc, mpk_alpha, known_vars, k_lone_vars, [], mpk_b
    )

    s, b0, y, x = symbols("s, b0, y, x")
    kenc = [alpha_1 + r1 * (b0 + y * b1), alpha_2 + r2 * (b0 + y * b1)]
    kenc = canonical(kenc)

    assert validate_k_encoding_format(
        kenc, mpk_alpha, [y], k_lone_vars, k_non_lone_vars, [b0, b1]
    )
    assert validate_c_encoding_format(
        [c_1_1, c_1_2, c_2_1, c_2_2], c_lone_vars, [], c_non_lone_vars, mpk_b
    )
    assert not validate_c_encoding_format(
        [s1, s2, c_2_2], c_lone_vars, [], c_non_lone_vars, mpk_b
    )

    assert validate_cp_encoding_format(
        [cp_1, cp_2], c_lone_vars, [], c_non_lone_vars, alphas
    )
    assert not validate_cp_encoding_format(
        [b1 * s_tilde, cp_1, cp_2], c_lone_vars, [], c_non_lone_vars, alphas
    )

    assert validate_cm_encoding_format(
        [s_tilde], c_lone_vars, [], c_non_lone_vars, mpk_alpha
    )
    assert validate_cm_encoding_format(
        [3 * s_tilde], c_lone_vars, [], c_non_lone_vars, mpk_alpha
    )
    assert not validate_cm_encoding_format(
        [3 * s_tilde + alpha_1], c_lone_vars, [], c_non_lone_vars, mpk_alpha
    )
    assert validate_cm_encoding_format(
        [3 * s_tilde + alpha_1 * s1], c_lone_vars, [], c_non_lone_vars, mpk_alpha
    )
    assert not validate_cm_encoding_format(
        [3 * s_tilde + alpha_1 * b1], c_lone_vars, [], c_non_lone_vars, mpk_alpha
    )

    # capture_vars_from_cm

    CM = 3 * s_tilde + alpha_1 * s1

    cm_lone_vars, cm_non_lone_vars = capture_vars_from_cm(
        CM, c_lone_vars, c_non_lone_vars, alphas, []
    )

    assert cm_lone_vars == [s_tilde]
    assert cm_non_lone_vars == [s1]

    # validate_vars_in_cm_encoding
    # tests:

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

    # MSK

    alphas = [alpha_1, alpha_2]

    # MPK encodings

    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    # key encodings

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    kenc = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    # ciphertext encodings

    CM = 3 * s_tilde + alpha_1 * s1 + alpha_2 * s2

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
        v1,
        v2,
        vp1,
        vp2,
    ]
    c_lone_vars = [s_tilde, v1, v2, vp1, vp2]
    c_non_lone_vars = [s1, s2, sp1, sp2]

    res, msg = validate_vars_in_cm_encoding(
        [alpha_1, alpha_2],
        [s_tilde],
        [s1],
        cenc,
        c_lone_vars,
        c_non_lone_vars,
        mpk,
        alphas,
        [],
        kenc,
    )
    assert res

    res, msg = validate_vars_in_cm_encoding(
        [alpha_1, alpha_2],
        [s_tilde],
        [s1],
        [c_1_2],
        c_lone_vars,
        c_non_lone_vars,
        mpk,
        alphas,
        [],
        kenc,
    )
    assert not res

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

    # MSK

    alphas = [alpha_1, alpha_2]

    # MPK encodings

    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    # key encodings

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    kenc = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    # ciphertext encodings

    CM = s_tilde

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
        v1,
        v2,
        vp1,
        vp2,
    ]
    c_lone_vars = [s_tilde, v1, v2, vp1, vp2]
    c_non_lone_vars = [s1, s2, sp1, sp2]

    res, msg = validate_vars_in_cm_encoding(
        [], [s_tilde], [], cenc, c_lone_vars, c_non_lone_vars, mpk, alphas, [], kenc
    )
    assert res

    # distributed IBE example scheme

    mpk_alpha = [alpha_1, alpha_2]
    mpk_b = [b0, b1]
    key_encoding = [alpha_1 + r1 * (b0 + y * b1), alpha_2 + r2 * (b0 + y * b1)]
    key_encoding = canonical(key_encoding)
    cm_encoding = canonical([(alpha_1 + alpha_2) * s])
    c_encoding = canonical([s * (b0 + x * b1)])
    unknown = [alpha_1, alpha_2, b0, b1, r1, r2, s]

    assert validate_k_encoding_format(
        key_encoding, mpk_alpha, [x, y], [], [r1, r2], mpk_b
    )
    assert validate_c_encoding_format(c_encoding, [], [x, y], [s], mpk_b)
    # assert validate_cp_encoding_format()
    assert validate_cm_encoding_format(cm_encoding, [], [x, y], [s], mpk_alpha)

    res, msg = validate_vars_in_cm_encoding(
        [alpha_1, alpha_2],
        [],
        [s],
        c_encoding,
        [],
        [s],
        [b0, b1],
        [alpha_1, alpha_2],
        [x, y],
        key_encoding,
    )

    assert res

    # incorrect distributed IBE example scheme

    mpk_alpha = [alpha_1, alpha_2]
    mpk_b = [b0, b1]
    key_encoding = [alpha_1 + r1 * (b0 + y * b1), alpha_2 + r2 * (b0 + y * b1)]
    key_encoding = canonical(key_encoding)
    cm_encoding = canonical([(alpha_1 + alpha_2 + b0) * s])
    c_encoding = canonical([s * (b0 + x * b1)])
    unknown = [alpha_1, alpha_2, b0, b1, r1, r2, s]

    assert validate_k_encoding_format(
        key_encoding, mpk_alpha, [x, y], [], [r1, r2], mpk_b
    )
    assert validate_c_encoding_format(c_encoding, [], [x, y], [s], mpk_b)
    # assert validate_cp_encoding_format()
    assert not validate_cm_encoding_format(cm_encoding, [], [x, y], [s], [b0, b1, b2])

    # capturing functions

    encodings = [x * vp1 + 3, s_tilde, vp1 + b1, alpha_1, b0, b1, alpha_2, vp2 * 3]

    captured_lone_vars = capture_lone_vars_from_encoding(
        encodings, [x], [alpha_1, alpha_2], mpk_b
    )

    assert captured_lone_vars == [vp1, s_tilde, vp2]

    assert not capture_lone_vars_from_encoding(key_encoding, [x, y], mpk_alpha, mpk_b)
    assert not capture_lone_vars_from_encoding(cm_encoding, [x, y], mpk_alpha, mpk_b)
    assert not capture_lone_vars_from_encoding(c_encoding, [x, y], mpk_alpha, mpk_b)

    # E.1 scheme

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
        v1,
        v2,
        vp1,
        vp2,
    ]
    c_lone_vars = [s_tilde, v1, v2, vp1, vp2]
    c_non_lone_vars = [s1, s2, sp1, sp2]
    mpk = [b1, bp1, b2, bp2, b_attr_1, b_attr_2]

    captured_lone_vars = capture_lone_vars_from_encoding(
        cenc, [], [alpha_1, alpha_2], mpk
    )
    assert not list(set(captured_lone_vars) ^ set(c_lone_vars))

    capture_non_lone_vars = capture_non_lone_vars_from_encoding(
        cenc, [], [alpha_1, alpha_2], mpk
    )
    assert capture_non_lone_vars == c_non_lone_vars

    k_1_1 = alpha_1 + r_GID * b1 + r1 * bp1
    k_1_2 = alpha_2 + r_GID * b2 + r2 * bp2
    k2_attr_1 = r1 * b_attr_1
    k2_attr_2 = r2 * b_attr_2

    kenc = [k_1_1, k_1_2, k2_attr_1, k2_attr_2]

    capture_non_lone_vars = capture_non_lone_vars_from_encoding(
        kenc, [], [alpha_1, alpha_2], mpk
    )
    assert capture_non_lone_vars == [r_GID, r1, r2]

    # distributed IBE example scheme with vars capture

    mpk_alpha = [alpha_1, alpha_2]
    mpk_b = [b0, b1]
    key_encoding = [alpha_1 + r1 * (b0 + y * b1), alpha_2 + r2 * (b0 + y * b1)]
    key_encoding = canonical(key_encoding)
    cm_encoding = canonical([(alpha_1 + alpha_2) * s])
    c_encoding = canonical([s * (b0 + x * b1)])
    cp_encoding = []

    unknown = [alpha_1, alpha_2, b0, b1, r1, r2, s]

    k_non_lone_vars = capture_non_lone_vars_from_encoding(
        key_encoding, [x, y], [alpha_1, alpha_2], mpk_b
    )
    k_lone_vars = capture_lone_vars_from_encoding(
        key_encoding, [x, y], [alpha_1, alpha_2], mpk_b
    )

    assert k_non_lone_vars == [r1, r2]
    assert not k_lone_vars

    c_non_lone_vars = capture_non_lone_vars_from_encoding(
        c_encoding, [x, y], [alpha_1, alpha_2], mpk_b
    )
    c_lone_vars = capture_lone_vars_from_encoding(
        c_encoding, [x, y], [alpha_1, alpha_2], mpk_b
    )

    assert c_non_lone_vars == [s]
    assert not c_lone_vars

    assert validate_k_encoding_format(
        key_encoding, mpk_alpha, [x, y], k_lone_vars, k_non_lone_vars, mpk_b
    )
    assert validate_c_encoding_format(
        c_encoding, c_lone_vars, [x, y], c_non_lone_vars, mpk_b
    )
    # assert validate_cp_encoding_format()

    assert validate_cm_encoding_format(
        cm_encoding, c_lone_vars, [x, y], c_non_lone_vars, mpk_alpha
    )

    res, msg = validate_vars_in_cm_encoding(
        [alpha_1, alpha_2],
        [],
        [s],
        c_encoding,
        [],
        [s],
        [b0, b1],
        [alpha_1, alpha_2],
        [x, y],
        key_encoding,
    )

    assert res

    # capture_alphas

    captured = capture_alphas_from_cm(cm_encoding, alphas)
    assert captured == [alpha_1, alpha_2]

    # validate_cm, distributed IBE

    # ok res, msg = validate_cm(c_encoding, cp_encoding, cm_encoding, key_encoding,  [alpha_1, alpha_2], mpk_b, [x, y])
    # assert res

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

    res, msg = validate_cm(
        [c_1_1, c_1_2, c_2_1, c_2_2],
        [cp_1, cp_2],
        CM,
        kenc,
        [alpha_1, alpha_2],
        mpk,
        [],
    )
    assert res

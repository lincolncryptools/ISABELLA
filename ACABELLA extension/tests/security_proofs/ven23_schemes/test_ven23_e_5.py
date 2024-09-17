from sympy import symbols, init_printing

init_printing(use_unicode=True)


def test_ven23_e_5():

    # Ven23 scheme in Appendix E.5 (modified)

    alpha1, alpha2, b, bp, b10, b11, b20, b21, rgid, r, x1, x2, y1, y2, s1, s2, stilde = symbols(
        "alpha1, alpha2, b, bp, b10, b11, b20, b21, rgid, r, x1, x2, y1, y2, s1, s2, stilde"
    )
    A11, A12, A21, A22 = symbols("A11, A12, A21, A22")
    v2, v2p = symbols("v2, v2p")

    # key for same user with gid at authority 1
    k1 = alpha1 + rgid * (b10 + y1 * b11)
    # key for user with gid at authority 2 
    k2 = alpha2 + rgid * (b20 + y2 * b21)
    k3 = rgid
    # ciphertext for attribute x1 hosted by authority 1
    c1 = A12*v2p + s1 * (b10 + x1 * b11)
    c2 = A11*stilde + A12*v2 + s1 * alpha1
    c3 = s1
    # ciphertext for attribute x2 hosted by authority 2
    c4 = A22*v2p + s2 * (b20 + x2 * b21)
    c5 = A21*stilde + A22*v2 + s2 * alpha2
    c6 = s2
    # the blinding value c_M is 
    cm = stilde
    # master keys (including master-key/semi-common) of authority 1
    mpk1 = alpha1
    mpk2 = b10
    mpk3 = b11
    # master keys (including master-key/semi-common) of authority 2
    mpk4 = alpha2
    mpk5 = b20
    mpk6 = b21

    # known values: x1, x2, y1, y2

    unknown = [alpha1, alpha2, b, bp, b10, b11, b20, b21, rgid, r, s1, s2, 
               stilde, v2, v2p]

    k = [k1, k2, k3]
    c = [c1, c2, c3, c4, c5, c6]
    mpk = [mpk1, mpk2, mpk3, mpk4, mpk5, mpk6]
    
    ## the test should reflect that the master public key is:
    # master-key/semi-common: alpha1, alpha2
    # common: b10, b11, b20, b21
    
    ## the test should reflect that the key encodings are:
    # polynomials: k1, k2
    # non-lone variables: rgid
    # lone variables: none
    
    ## the test should reflect that the ciphertext encodings are:
    # non-primed polynomials: c1, c4
    # primed polynomials: c2, c5
    # non-lone variables: s1, s2
    # lone variables: v2, v2p
    # blinding value: cm

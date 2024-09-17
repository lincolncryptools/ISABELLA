from sympy import symbols, init_printing

from acabella.core.proof.security import SecurityAttack

init_printing(use_unicode=True)


def test_new_cpabe():

    # new scheme

    (
        alpha,
        b,
        b00,
        b01,
        b10,
        b11,
        r,
        s,
        sp,
        spp,
        x1,
        x2,
        y,
        yilab,
        yiatt,
        xilab,
        xiatt,
        xilab2,
        xiatt2,
    ) = symbols(
        "alpha, b, b00, b01, b10, b11, r, s, sp, spp, x1, x2, y, yilab, yiatt, xilab, xiatt, xilab2, xiatt2"
    )

    k1 = alpha + r * b
    k2 = r * (b00 + yilab * b01 + b10 + yiatt * b11)
    c1 = s * b + sp * (b00 + xilab * b01) + sp * b10
    c1p = sp * b11
    c2 = s
    c3 = sp
    c4 = s * b + spp * (b00 + xilab2 * b01) + spp * (b10 + xiatt2 * b11)
    c5 = spp
    mpk1 = b00
    mpk2 = b01
    mpk3 = b10
    mpk4 = b11
    mpk5 = b

    # known values: x, y

    unknown = [alpha, b, b00, b01, b10, b11, r, s, sp, spp]

    k = [k1, k2]
    c = [c1, c1p, c2, c3, c4, c5]
    mpk = [mpk1, mpk2, mpk3, mpk4, mpk5]

    # security_analysis(alpha, s, k, c, mpk, unknown, [], [])

    security_attack = SecurityAttack()
    security_attack.init(alpha * s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())
    security_attack.show_proof()

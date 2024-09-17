#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""
Decryption key attack against the NDCW15 scheme [1]

- Complete decryption attack

[1] J. Ning, X. Dong, Z. Cao, and L. Wei, “Accountable Authority Ciphertext-Policy
Attribute-Based Encryption with White-Box Traceability and Public Auditing in
the Cloud”, in ESORICS 15, pp. 270-289, Springer, 2015.
"""

from sympy import symbols

from acabella.core.cryptanalysis.decryption import DecryptionAttack, DecryptionKeyCorruptionModel


def test_ndcw15():

    alpha, b1, b2, s, x1, x2, x3 = symbols("alpha, b1, b2, s, x1, x2, x3")

    gp1 = b1
    gp2 = b2
    gp3 = 1

    k1 = alpha * (1 / (b1 + x3)) + x2 * b2 * (1 / (b1 + x3))
    k2 = x1
    k3 = x1 * b1
    c1 = s
    c2 = s * b1
    c3 = s * b2

    gp = [gp1, gp2, gp3]
    k = [k1, k2, k3]
    c = [c1, c2, c3]
    mpk = []

    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha * s, k, c, mpk, gp, [alpha, b1, b2, s])

    # set corruption model
    decryption_attack.set_corruption_model(DecryptionKeyCorruptionModel.NoCorruption)

    decryption_attack.run()
    msg = decryption_attack.show_solution()

    assert (
        msg.strip() == "[*] Decryption attack found: k0*c0*x3 + 1*k0*c1 + -x2/x1*k1*c2"
    ), "[!] No solution found"
    print(msg)
    decryption_attack.format_encodings()

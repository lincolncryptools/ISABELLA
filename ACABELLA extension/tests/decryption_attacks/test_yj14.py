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
Decryption key attack against the YJ14 scheme [1]

- Complete decryption attack
- Requires the corruption of one Attribute Authority [i]

[1] . K. Yang, and X. Jia, “Expressive, Efficient, and Revocable Data Access Control for
Multi-Authority Cloud Storage”, in IEEE Transactions on Parallel and Distributed
Systems, 25(7), IEEE, 2014.
"""

from sympy import symbols

from acabella.core.cryptanalysis.decryption import (
    DecryptionAttack,
    DecryptionKeyCorruptionModel,
    DecryptionKeyCorruptedVariable,
)


def test_yj14():

    alpha_i, b, bp, r, x, s = symbols("alpha_i, b, bp, r, x, s")

    k1 = alpha_i + x * b + r * bp
    k2 = r
    c1 = s
    c2 = s * bp
    mpk1 = b
    mpk2 = bp
    k = [k1, k2]
    c = [c1, c2]
    mpk = [mpk1, mpk2]
    gp = []

    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha_i * s, k, c, mpk, gp, [alpha_i, b, bp, r, s, x])

    # structure of AA[i]

    decryption_attack.add_mpk_AAj(alpha_i)
    decryption_attack.add_mpk_AAj(x)

    decryption_attack.add_misc(x)

    # set corruption model

    decryption_attack.set_corruption_model(DecryptionKeyCorruptionModel.AA)

    # perform corruption

    decryption_attack.add_corruptable_var(DecryptionKeyCorruptedVariable.misc, x)

    # run attack

    decryption_attack.run()

    msg = decryption_attack.show_solution()
    assert (
        msg.strip()
        == "[*] Decryption attack found: 1*k0[i]*c0 + -1*k1[i]*c1 + -x*c0*mpk0"
    ), "[!] No solution found"
    print(msg)
    decryption_attack.format_encodings()

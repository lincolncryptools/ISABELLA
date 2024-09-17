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
Decryption key attack against the YJR13 scheme [1][2]

- Complete decryption attack

[1] K. Yang, X. Jia, K. Ren, and B. Zhang, “DAC-MACS: Effective Data Access
Control for Multiauthority Cloud Storage Systems”, in INFOCOM 13, pp. 2895-
2903, IEEE, 2013.
[2] K. Yang, X. Jia, K. Ren, B. Zhang, and R. Xie, “DAC-MACS: Effective Data
Access Control for Multiauthority Cloud Storage Systems”, in TIFS, 8(11), pp.
1790 - 1801, IEEE, 2013.
"""

from sympy import symbols
from acabella.core.cryptanalysis.decryption import (
    DecryptionAttack,
    DecryptionKeyCorruptionModel,
)


def test_yjr13():

    alpha, b, bp, r, s, x1, x2 = symbols("alpha, b, bp, r, s, x1, x2")

    k1 = alpha * (1 / x1) + x2 * b + r * (b / bp)
    k2 = r * bp * (1 / x1)
    k3 = r * b
    c1 = s
    c2 = s / bp
    mpk1 = bp
    gp1 = b

    # known values by the attacker
    # without the need of corruption

    known1 = x1
    known2 = x2

    k = [k1, k2, k3]
    c = [c1, c2]
    mpk = [mpk1]
    gp = [gp1]

    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha * s, k, c, mpk, gp, [alpha, r, s, b, bp])

    # set corruption model
    decryption_attack.set_corruption_model(DecryptionKeyCorruptionModel.NoCorruption)

    decryption_attack.run()
    msg = decryption_attack.show_solution()

    assert (
        msg.strip()
        == "[*] Decryption attack found: k0*c0*x1 + -x1*k2*c1 + -x1*x2*c0*gp0"
    ), "[!] No solution found"
    print(msg)
    decryption_attack.format_encodings()

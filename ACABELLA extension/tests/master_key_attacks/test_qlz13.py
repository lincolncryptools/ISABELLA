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
Master key attack against the QLZ13 scheme [1]

[1] H. Qian, J. Li, and Y. Zhang, “Privacy-Preserving Decentralized Ciphertext-Policy
Attribute-Based Encryption with Fully Hidden Access Structure”, in ICICS 13, pp.
363 372, Springer, 2013
"""

import sympy as sp

from acabella.core.cryptanalysis.master_key import MasterKeyAttack

sp.init_printing(use_unicode=True)


def test_qlz13():

    alpha, b, b1, bp, r, rp, x = sp.symbols("alpha, b, b1, bp, r, rp, x")
    k1 = alpha + r * b + b1 / (x + bp)
    k0 = r * b - rp * b1
    k2 = (rp + 1 / (x + bp)) * b1

    k = [k0, k1, k2]

    master_key_attack = MasterKeyAttack()
    master_key_attack.init(alpha, k, [alpha, b, b1, bp, r, rp, x])
    master_key_attack.run()
    msg = master_key_attack.show_solution()

    assert (
        msg.strip() == "[*] Master key attack found: -1*k0 + 1*k1 + -1*k2"
    ), "[!] No master key attack found"
    print(msg)
    master_key_attack.format_encodings()

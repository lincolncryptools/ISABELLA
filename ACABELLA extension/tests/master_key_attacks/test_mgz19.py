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
Master key attack against the MGZ19 scheme [1]

- Based on corruption of the central authority (CA)
- Attacker recovers [r] from CA

[1] C. Ma, A. Ge, and J. Zhang, “Fully Secure Decentralized Ciphertext-Policy
Attribute-Based Encryption in Standard Model”, in Inscrypt 19, pp. 427 - 447,
Springer, 2019.
"""

import sympy as sp

from acabella.core.cryptanalysis.master_key import (
    MasterKeyAttack,
    MasterKeyCorruptionModel,
    MasterKeyCorruptedVariable,
)

sp.init_printing(use_unicode=True)


def test_mgz19():

    alpha_j, b_j, r = sp.symbols("alpha_j, b_j, r")
    k0 = alpha_j + r * b_j
    mpk = b_j
    k = [k0]

    corruptable_vars_from_CA = [r]

    master_key_attack = MasterKeyAttack()
    master_key_attack.init(alpha_j, k, [alpha_j, b_j, r])

    # add AA master pair

    master_key_attack.add_mpk_AA(alpha_j)
    master_key_attack.add_mpk_AA(b_j)

    # add CA master pair

    master_key_attack.add_mpk_CA(r)

    # set corruption model mixed_CA: CA/CAs and AAs are involved.
    # However only CAs are corruptable.
    master_key_attack.set_corruption_model(MasterKeyCorruptionModel.mixed_CA)

    # add mpk

    master_key_attack.add_mpk(mpk)

    # add corruptable variables

    master_key_attack.add_corruptable_var(
        MasterKeyCorruptedVariable.MPK_CA, corruptable_vars_from_CA[0]
    )

    master_key_attack.run()
    msg = master_key_attack.show_solution()

    assert (
        msg.strip() == "[*] Master key attack found: 1*k0[i][j] + -r*mpk_i_j"
    ), "[!] No master key attack found"
    print(msg)
    master_key_attack.format_encodings()

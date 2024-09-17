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
Master key attack against the LXXH16 scheme [1]

- Based on corruption of the central authority (CA)
- Attacker recovers [b] from CA

[1] W. Li, K. Xue, Y. Xue, and J. Hong, “TMACS: A Robust and Verifiable Threshold
Multi-Authority Access Control System in Public Cloud Storage”, in IEEE
Transactions on Parallel and Distributed Systems, 27(5), pp. 1484 - 1496, IEEE, 2016.
"""

import sympy as sp

from acabella.core.cryptanalysis.master_key import (
    MasterKeyAttack,
    MasterKeyCorruptionModel,
    MasterKeyCorruptedVariable,
)

sp.init_printing(use_unicode=True)


def test_lxxh16():

    alpha_i, r, b = sp.symbols("alpha_i, r, b")

    k0 = alpha_i + r * b
    k1 = r
    k = [k0, k1]

    corruptable_vars_from_CA = [b]

    master_key_attack = MasterKeyAttack()
    master_key_attack.init(alpha_i, k, [alpha_i, r, b])

    # add CA encodings

    master_key_attack.add_mpk_CA(b)

    # add AA encodings

    master_key_attack.add_mpk_AA(alpha_i)

    # set corruption model

    master_key_attack.set_corruption_model(MasterKeyCorruptionModel.mixed_CA)

    # add corruptable variables

    for var in corruptable_vars_from_CA:
        master_key_attack.add_corruptable_var(MasterKeyCorruptedVariable.MPK_CA, var)

    master_key_attack.run()
    msg = master_key_attack.show_solution()

    assert (
        msg.strip() == "[*] Master key attack found: 1*k0[i][j] + -b*k1[i][j]"
    ), "[!] No master key attack found"
    print(msg)
    master_key_attack.format_encodings()

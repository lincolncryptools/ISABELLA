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
Master key attack against the YJ12 scheme [1]

- Based on corruption of one attribute authority.
- Attacker recovers [alpha_p, b/bp] from CA

[1] K. Yang, and X. Jia, “Attribute-Based Access Control for Multi-Authority Systems
in Cloud Storage”, in 2012 32nd IEEE International Conference on Distributed
Computing Systems, pp. 536 - 545, IEEE, 2012.
"""

import sympy as sp

from acabella.core.cryptanalysis.master_key import (
    MasterKeyAttack,
    MasterKeyCorruptionModel,
    MasterKeyCorruptedVariable,
)

sp.init_printing(use_unicode=True)


def test_yj12():

    alpha_i, ap, divb, bp, r, b = sp.symbols("alpha_i, ap, divb, bp, r, b")
    k1 = r
    k0 = r * b / bp + alpha_i / bp
    k = [k0, k1]

    corruptable_vars_from_CA = [ap, b / bp]

    master_key_attack = MasterKeyAttack()
    master_key_attack.init(alpha_i, k, [alpha_i, r])

    # add AA master pair

    master_key_attack.add_mpk_AA(alpha_i)
    master_key_attack.add_mpk_AA(b / bp)

    # add global parameters

    master_key_attack.add_gp_variable(bp)
    master_key_attack.add_gp_variable(divb)

    # set corruption model

    master_key_attack.set_corruption_model(MasterKeyCorruptionModel.mixed_AA)

    # add corruptable variables

    master_key_attack.add_corruptable_var(
        MasterKeyCorruptedVariable.MPK_AA, corruptable_vars_from_CA[1]
    )

    master_key_attack.run()
    msg = master_key_attack.show_solution()

    assert (
        msg.strip() == "[*] Master key attack found: bp*k0[i] + -b*k1[i]"
    ), "[!] No master key attack found"
    print(msg)
    master_key_attack.format_encodings()

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

from acabella.core.common.parse_config import ParseConfig
from acabella.core.cryptanalysis.conditional import ConditionalDecryptionAttack


def test_jlww13():

    parse_config = ParseConfig()
    parse_config.init("tests/analysis/configs/jlww13.json")
    cd_config = parse_config.generate_conditional_params()

    cd_attack = ConditionalDecryptionAttack()
    cd_attack.init(
        cd_config["alpha"],
        cd_config["special_s"],
        cd_config["mpk"],
        cd_config["k_fixed"],
        cd_config["k_att"],
        cd_config["c_fixed"],
        cd_config["c_att"],
        cd_config["unknown"],
        cd_config["prefixes"],
        cd_config["nr_indexed_encodings"],
    )
    cd_attack.run()
    msg = cd_attack.show_solution()

    assert (
        msg[0].strip()
        == "[*] Conditional decryption attack found: 1*k0*c1 + 1*k0*c3 + -1*k1*c1 + 1*k2*c0 + -1*k5*c3 + 1*k6*c2"
    )

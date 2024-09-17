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

from acabella.core.cryptanalysis.analysis import AnalysisWithCorruption
from acabella.core.common.parse_config import ParseConfig


def test_cm14():

    parse_config = ParseConfig()
    parse_config.init("tests/analysis/configs/cm14.json")
    dec_params, corruptable_vars_from_A = parse_config.generate_dec_key_params()

    master_params = None

    print("\n\n[*] Analyzing scheme...\n\n")

    analysis = AnalysisWithCorruption()
    analysis.init(master_params, dec_params, None, corruptable_vars_from_A, None)

    analysis.run()
    msgs, _, _ = analysis.show_solution()

    assert msgs[2].strip() == "[*] Decryption attack found: 1*k0[i]*c0 + -1/b2*k1[i]*c1"

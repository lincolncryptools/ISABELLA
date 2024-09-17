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


def test_lxxh16():

    parse_config = ParseConfig()
    parse_config.init("tests/analysis/configs/lxxh16.json")
    master_params, corruptable_vars_from_CA = parse_config.generate_master_key_params()

    dec_params = None

    print("\n\n[*] Analyzing scheme...\n\n")

    analysis = AnalysisWithCorruption()
    analysis.init(master_params, dec_params, corruptable_vars_from_CA, None, None)

    analysis.run()
    msgs, _, _ = analysis.show_solution()

    assert (
        msgs[2].strip()
        == "[*] Master key attack with corruption found: 1*k0[i][j] + -b*k1[i][j]"
    )

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


def test_bsw07():

    parse_config = ParseConfig()
    parse_config.init("tests/analysis/configs/bsw07.json")
    security_params = parse_config.generate_security_analysis_params()

    print("\n\n[*] Analyzing scheme...\n\n")

    analysis = AnalysisWithCorruption()

    analysis.init(None, None, None, None, security_params)
    analysis.run()
    msg = analysis.show_solution()
    print(msg)

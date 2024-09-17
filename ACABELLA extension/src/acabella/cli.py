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

"""acabella_cmd.py: Command line tool for analyzing ABE schemes
based on JSON inputs"""

import argparse
from acabella.core.common.parse_config import ParseConfig
from acabella.core.cryptanalysis.analysis import AnalysisWithCorruption
from acabella.core.cryptanalysis.conditional import ConditionalDecryptionAttack


def setup_parser():
    parser = argparse.ArgumentParser(description="ACABELLA cli for ABE scheme analysis")

    # Define flags for each analysis type, each accepting a configuration file
    parser.add_argument(
        "--master-key",
        "-m",
        metavar="CONFIG",
        help="Config file for Master Key attack analysis",
    )
    parser.add_argument(
        "--decryption",
        "-d",
        metavar="CONFIG",
        help="Config file for Decryption attack analysis",
    )
    parser.add_argument(
        "--security",
        "-s",
        metavar="CONFIG",
        help="Config file for Security analysis",
    )
    parser.add_argument(
        "--conditional",
        "-c",
        metavar="CONFIG",
        help="Config file for Conditional attack analysis",
    )
    parser.add_argument(
        "--all",
        "-a",
        metavar="CONFIG",
        help="Config file for performing all types of analyses",
    )
    parser.add_argument(
        "--insecure-only",
        "-i",
        metavar="CONFIG",
        help="Config file for comprehensive analysis if scheme is detected as insecure",
    )

    return parser


def run_analysis(args):
    if args.all:
        # Assuming a method exists that can handle all analyses with a single config
        run_all_analyses(args.all)
    else:
        if args.master_key:
            run_master_key_attack(args.master_key)
        if args.decryption:
            run_decryption_attack(args.decryption)
        if args.security:
            run_security_analysis(args.security)
        if args.conditional:
            run_conditional_attack(args.conditional)
        if args.insecure_only:
            run_insecure_only_analysis(args.insecure_only)


def run_master_key_attack(config_path: str):
    config = ParseConfig()
    config.init(config_path)
    analysis = AnalysisWithCorruption()
    master_params, corruptable_vars = config.generate_master_key_params()
    analysis.init(master_key_params=master_params, corruptable_vars_MK=corruptable_vars)
    analysis.run()
    analysis.show_solution()


def run_decryption_attack(config_path: str):
    config = ParseConfig()
    config.init(config_path)
    analysis = AnalysisWithCorruption()
    dec_params, corruptable_vars = config.generate_dec_key_params()
    analysis.init(
        decryption_key_params=dec_params, corruptable_vars_DK=corruptable_vars
    )
    analysis.run()
    analysis.show_solution()


def run_security_analysis(config_path: str):
    config = ParseConfig()
    config.init(config_path)
    analysis = AnalysisWithCorruption()
    security_params = config.generate_security_analysis_params()
    analysis.init(security_analysis_params=security_params)
    analysis.run()
    analysis.show_solution()


def run_conditional_attack(config_path: str):
    config = ParseConfig()
    config.init(config_path)
    cd_attack = ConditionalDecryptionAttack()
    cd_config = config.generate_conditional_params()
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
    cd_attack.show_solution()


def run_insecure_only_analysis(config_path: str):
    config = ParseConfig()
    config.init(config_path)
    analysis = AnalysisWithCorruption()
    (
        security_params,
        master_params,
        corruptable_vars_master,
        dec_params,
        corruptable_vars_dec,
    ) = config.generate_all_params()

    analysis.init(
        master_key_params=master_params,
        decryption_key_params=dec_params,
        corruptable_vars_MK=corruptable_vars_master,
        corruptable_vars_DK=corruptable_vars_dec,
        security_analysis_params=security_params,
    )
    analysis.run_logic()
    analysis.show_solution()


def run_all_analyses(config_path: str):
    config = ParseConfig()
    config.init(config_path)
    analysis = AnalysisWithCorruption()
    (
        security_params,
        master_params,
        corruptable_vars_master,
        dec_params,
        corruptable_vars_dec,
    ) = config.generate_all_params()

    analysis.init(
        master_key_params=master_params,
        decryption_key_params=dec_params,
        corruptable_vars_MK=corruptable_vars_master,
        corruptable_vars_DK=corruptable_vars_dec,
        security_analysis_params=security_params,
    )
    analysis.run()
    analysis.show_solution()


def main():
    parser = setup_parser()
    args = parser.parse_args()
    run_analysis(args)


if __name__ == "__main__":
    main()

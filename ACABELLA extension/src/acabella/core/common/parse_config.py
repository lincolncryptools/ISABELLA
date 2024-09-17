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


"""parse_config.py: JSON parser for ACABELLA analysis"""

import json
from sympy import *
from acabella.core.common.utils import *

init_printing(use_unicode=True)


class ParseConfig:
    """
    This class parses the JSON input files for ACABELLA involving
    all type of checks: master key attacks, decryption attacks,
    security analysis via AC17, etc.

    Attributes:
        json_parsed (string): Resulting string after JSON parsing.
    """

    def __init__(self) -> None:
        self.json_parsed = None

    def init(self, config_file: str) -> None:
        """
        Initializes the parser with a json configuration file
        that describes the analysis.

        Parameters:
            config_file (str): Path to the JSON file.
        """
        with open(config_file, "r") as read_file:
            self.json_parsed = json.load(read_file)

    def init_with_str(self, data: str) -> None:
        """
        It is also possible to initialize the parser with
        a string containing JSON instead of using a file
        that needs to be open, read, etc.

        Parameters:
            data (str): String containing JSON code.
        """
        self.json_parsed = json.loads(data)

    def generate_master_key_params(self) -> tuple[dict, list]:
        """
        Based on the JSON input files, it generates a dictionary
        with the corresponding parameters to look for master key
        attacks. If a list of corruptable variables is supplied,
        it also generates a list of those variables.

        Returns:
                Tuple (tuple): Master key attack parameters and corruptable variables.
        """

        if self.json_parsed is None:
            print("parse_config object is not initialized")
            return None, None

        master_params = {}
        corruptable_vars = {}

        try:
            master_params["keyenco"] = [parse_expr(x) for x in self.json_parsed["k"]]
            master_params["masterkey"] = parse_expr(self.json_parsed["master_key"])
            master_params["unknown"] = [
                parse_expr(x) for x in self.json_parsed["unknown_vars"]
            ]
            master_params["corruption_model"] = self.json_parsed["corruption_model"]

            master_params["MPK_CA"] = [
                parse_expr(x) for x in self.json_parsed["MPK_CA"]
            ]
            master_params["MPK_AA"] = [
                parse_expr(x) for x in self.json_parsed["MPK_AA"]
            ]
            master_params["MPK_vars"] = [
                parse_expr(x) for x in self.json_parsed["MPK_vars"]
            ]
            master_params["GP_vars"] = [
                parse_expr(x) for x in self.json_parsed["GP_vars"]
            ]

            corruptable_vars = self.json_parsed["corruptable_vars"]
        except:
            master_params = None

        return master_params, corruptable_vars

    def generate_dec_key_params(self) -> tuple[dict, list]:
        """
        Based on the JSON input files, it generates a dictionary
        with the corresponding parameters to look for decryption
        attacks. If a list of corruptable variables is supplied,
        it also generates a list of those variables.

        Returns:
            Tuple (tuple): Decryption attack parameters and corruptable variables
        """

        if self.json_parsed is None:
            print("parse_config object is not initialized")
            return None, None

        # prepare decryption params

        dec_params = {}
        corruptable_vars = []

        try:
            dec_params["key"] = parse_expr(self.json_parsed["key"])
            dec_params["k_encodings"] = [parse_expr(x) for x in self.json_parsed["k"]]
            dec_params["c_encodings"] = [parse_expr(x) for x in self.json_parsed["c"]]
            dec_params["mpk_encodings"] = [
                parse_expr(x) for x in self.json_parsed["mpk"]
            ]
            dec_params["gp_encodings"] = [parse_expr(x) for x in self.json_parsed["gp"]]
            dec_params["unknown"] = [
                parse_expr(x) for x in self.json_parsed["unknown_vars"]
            ]

            dec_params["corruption_model"] = self.json_parsed["corruption_model"]

            # NOTE We suppose every field is always available in the JSON file.
            # It will be empty if it is not related to a particular corruption model.

            dec_params["MPK_AAi"] = [parse_expr(x) for x in self.json_parsed["MPK_AAi"]]
            dec_params["MPK_AAj"] = [parse_expr(x) for x in self.json_parsed["MPK_AAj"]]

            dec_params["misc_vars"] = [
                parse_expr(x) for x in self.json_parsed["misc_vars"]
            ]

            corruptable_vars = self.json_parsed["corruptable_vars"]
        except:
            dec_params = None

        return dec_params, corruptable_vars

    def generate_conditional_params(self) -> tuple[dict, list]:
        """
        Based on the JSON input files, it generates a dictionary
        with the corresponding parameters to look for conditional
        attacks. If a list of corruptable variables is supplied,
        it also generates a list of those variables.

        Returns:
            Parameters (dict): Conditional attack parameters.
        """

        if self.json_parsed is None:
            print("parse_config object is not initialized")
            return None, None

        """
        TODO: Some of this configuration generation can be automated e.g.
            # these are fixed in the system
            att_mpk_group = parse_expr("att_mpk_group")
            att_scalar = parse_expr("att_scalar")
            policy_share = parse_expr("lambda_policy_share")

            k_fixed_1 = alpha + r
            k_att_1 = r + get_indexed_encoding("rp", 1)*att_mpk_group
            k_att_2 = get_indexed_encoding("rp", 1)
            c_att_1 = policy_share*att_mpk_group
            c_att_2 = policy_share
            mpk1 = att_mpk_group
            special_s = s
        """

        try:
            att_mpk_group = parse_expr("att_mpk_group")
            att_scalar = parse_expr("att_scalar")
            policy_share = parse_expr("lambda_policy_share")

            mpk1 = att_mpk_group
            special_s = parse_expr("s")
            k_fixed = [parse_expr(x) for x in self.json_parsed["k_fixed"]]
            k_att = [parse_expr(x) for x in self.json_parsed["k_indexed"]]
            c_fixed = [parse_expr(x) for x in self.json_parsed["c_fixed"]]
            c_att = [parse_expr(x) for x in self.json_parsed["c_indexed"]]
            unkown = [parse_expr(x) for x in self.json_parsed["unknown"]]

            mpk = []

            prefixes = ["rp"]
            nr_indexed_encodings = 1

            # prepare conditional params

            cd_params = {}
            cd_params["alpha"] = parse_expr("alpha")
            cd_params["special_s"] = special_s
            cd_params["mpk"] = mpk
            cd_params["k_fixed"] = k_fixed
            cd_params["k_att"] = k_att
            cd_params["c_fixed"] = c_fixed
            cd_params["c_att"] = c_att
            cd_params["unkown"] = ([],)
            cd_params["prefixes"] = prefixes
            cd_params["nr_indexed_encodings"] = nr_indexed_encodings
            cd_params["unknown"] = unkown
        except:
            cd_params = None

        return cd_params

    def generate_abgw_bridge_params(self) -> tuple[dict, list]:
        """
        Based on the JSON input files, it generates a dictionary
        with the corresponding parameters to transform a description
        of an ABE scheme in ACABELLA format into a configuration file
        to the tool that creates inputs for the ABGW tool in order
        to check the security of the scheme.

        Returns:
            Parameters (dict): ABGW parameters.
        """

        if self.json_parsed is None:
            print("parse_config object is not initialized")
            return None, None

        try:
            k = [parse_expr(x) for x in self.json_parsed["k"]]
            c = [parse_expr(x) for x in self.json_parsed["c"]]
            mpk = [parse_expr(x) for x in self.json_parsed["mpk"]]
            gp = [parse_expr(x) for x in self.json_parsed["gp"]]

            # prepare abgw params

            abgw_params = {}
            abgw_params["key"] = parse_expr(self.json_parsed["key"])
            abgw_params["k_encodings"] = k
            abgw_params["c_encodings"] = c
            abgw_params["mpk_encodings"] = mpk
            abgw_params["gp_encodings"] = gp

            abgw_params["unknown"] = [
                parse_expr(x) for x in self.json_parsed["unknown_vars"]
            ]
            abgw_params["known"] = [
                parse_expr(x) for x in self.json_parsed["known_vars"]
            ]
        except:
            abgw_params = None

        return abgw_params

    def generate_security_analysis_params(self) -> tuple[dict, list]:
        """
        Based on the JSON input files, it generates a dictionary
        with the corresponding parameters to perform a security
        analysis of the provided scheme.

        Returns:
            Parameters (dict): Security analysis parameters.
        """

        if self.json_parsed is None:
            print("parse_config object is not initialized")
            return None, None

        # prepare security_analysis_params

        security_analysis_params = {}

        try:
            security_analysis_params["key"] = parse_expr(self.json_parsed["key"])
            security_analysis_params["k_encodings"] = [
                parse_expr(x) for x in self.json_parsed["k"]
            ]
            security_analysis_params["c_encodings"] = [
                parse_expr(x) for x in self.json_parsed["c"]
            ]
            security_analysis_params["mpk_encodings"] = [
                parse_expr(x) for x in self.json_parsed["mpk"]
            ]
            security_analysis_params["unknown"] = [
                parse_expr(x) for x in self.json_parsed["unknown_vars"]
            ]
            security_analysis_params["corruptable_vars"] = [
                parse_expr(x) for x in self.json_parsed["corruptable_vars"]
            ]
        except:
            security_analysis_params = None

        return security_analysis_params

    def generate_all_params(self):
        """
        Based on the JSON input files, it generates a dictionary
        with the corresponding parameters to look for decryption
        and master key attacks as well as to check the security
        of the provided ABE scheme.

        Returns:
            Parameters (dict): All involved parameters.
        """
        if self.json_parsed is None:
            print("parse_config object is not initialized")
            return None, None

        master_params = {}
        corruptable_vars_master = {}
        dec_params = {}
        corruptable_vars_dec = {}

        # parse security params

        security_params_json = None
        security_params = {}

        try:
            security_params_json = self.json_parsed["security"]
            security_params["key"] = parse_expr(security_params_json["key"])
            security_params["k_encodings"] = [
                parse_expr(x) for x in security_params_json["k"]
            ]
            security_params["c_encodings"] = [
                parse_expr(x) for x in security_params_json["c"]
            ]
            security_params["mpk_encodings"] = [
                parse_expr(x) for x in security_params_json["mpk"]
            ]
            security_params["unknown"] = [
                parse_expr(x) for x in security_params_json["unknown_vars"]
            ]
            security_params["corruptable_vars"] = [
                parse_expr(x) for x in security_params_json["corruptable_vars"]
            ]
        except:
            security_params = None

        # parse dec params

        dec_params_json = None
        corruptable_vars_dec = None
        dec_params = {}

        try:
            dec_params_json = self.json_parsed["decryption"]
            dec_params["key"] = parse_expr(dec_params_json["key"])
            dec_params["k_encodings"] = [parse_expr(x) for x in dec_params_json["k"]]
            dec_params["c_encodings"] = [parse_expr(x) for x in dec_params_json["c"]]
            dec_params["mpk_encodings"] = [
                parse_expr(x) for x in dec_params_json["mpk"]
            ]
            dec_params["gp_encodings"] = [parse_expr(x) for x in dec_params_json["gp"]]
            dec_params["unknown"] = [
                parse_expr(x) for x in dec_params_json["unknown_vars"]
            ]
            dec_params["corruption_model"] = dec_params_json["corruption_model"]

            # NOTE We suppose every field is always available in the JSON file.
            # It will be empty if it is not related to a particular corruption model.

            dec_params["MPK_AAi"] = [parse_expr(x) for x in dec_params_json["MPK_AAi"]]
            dec_params["MPK_AAj"] = [parse_expr(x) for x in dec_params_json["MPK_AAj"]]
            dec_params["misc_vars"] = [
                parse_expr(x) for x in dec_params_json["misc_vars"]
            ]
            corruptable_vars_dec = dec_params_json["corruptable_vars"]
        except:
            dec_params = None

        # parse master params

        master_params_json = None
        corruptable_vars_master = None

        try:
            master_params_json = self.json_parsed["master_key"]

            master_params["keyenco"] = [parse_expr(x) for x in master_params_json["k"]]
            master_params["masterkey"] = parse_expr(master_params_json["master_key"])
            master_params["unknown"] = [
                parse_expr(x) for x in master_params_json["unknown_vars"]
            ]
            master_params["corruption_model"] = master_params_json["corruption_model"]

            master_params["MPK_CA"] = [
                parse_expr(x) for x in master_params_json["MPK_CA"]
            ]
            master_params["MPK_AA"] = [
                parse_expr(x) for x in master_params_json["MPK_AA"]
            ]
            master_params["MPK_vars"] = [
                parse_expr(x) for x in master_params_json["MPK_vars"]
            ]
            master_params["GP_vars"] = [
                parse_expr(x) for x in master_params_json["GP_vars"]
            ]
            corruptable_vars_master = master_params_json["corruptable_vars"]
        except:
            master_params = None

        return (
            security_params,
            master_params,
            corruptable_vars_master,
            dec_params,
            corruptable_vars_dec,
        )

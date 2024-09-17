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

"""analysis.py: Definition of the analysis class that aims to perform different tests on a given ABE scheme"""

from sympy import *
from acabella.core.cryptanalysis.attack import *
from acabella.core.proof.security import SecurityAttack
from acabella.core.cryptanalysis.master_key import *
from acabella.core.cryptanalysis.decryption import *

init_printing(use_unicode=True)

DEBUG = False


class Analysis:
    """
    Base analysis class with methods to perform basic master key and
    decryption attacks. AnalysisWithCorruption inherits this class
    and extends to also provide security analysis of the ABE scheme.

    Attributes:
        analysis_list (list): List of analysis to perform by the class via run.
        sol_list (list): Solutions found via the analysis in analysis_list.
    """

    def __init__(self) -> None:
        """
        The constructor for the Analysis class.
        """
        self.analysis_list = []
        self.sol_list = []

    def init(self, master_key_params: dict, decryption_key_params: dict) -> None:
        """
        Initializes the analysis class with the respective params for
        master key attacks and decryption attacks :

        Parameters:
            master_key_params (dict): The parameters required for a master key attack.
            decryption_key_params (dict): The parameters required for a decryption key attack.
        """
        master_key_attack = MasterKeyAttack()
        master_key_attack.init(
            master_key_params["masterkey"],
            master_key_params["keyenco"],
            master_key_params["unknown"],
        )

        decryption_attack = DecryptionAttack()
        decryption_attack.init(
            decryption_key_params["key"],
            decryption_key_params["all_p"],
            decryption_key_params["unknown"],
        )

        self.analysis_list.append(decryption_attack)
        self.analysis_list.append(master_key_attack)

    def run(self) -> None:
        """
        Tries to find master key and decryption attacks in the
        provided ABE scheme.
        """
        for attack in self.analysis_list:
            if attack.enabled == True:
                attack.run()

    def show_solution(self) -> list:
        """
        Returns the result of the attacks.

        Returns:
            solution (list): The result of the attacks.
        """
        for attack in self.analysis_list:
            self.sol_list.append(attack.show_solution())
        return self.sol_list


class AnalysisWithCorruption(Analysis):
    """
    This class performs the security analysis of the provided
    scheme as well as look for master and decryption attacks if
    sufficient parameters are provided.
    """

    def __init__(self) -> None:
        self.corruptable_vars_MK = []
        self.corruptable_vars_DK = []

        super().__init__()

    def init(
        self,
        master_key_params: dict = None,
        decryption_key_params: dict = None,
        corruptable_vars_MK: list = None,
        corruptable_vars_DK: list = None,
        security_analysis_params: dict = None,
    ) -> bool:
        """
        Initializes the AnalysisWithCorruption class.

        Parameters:
            master_key_params (dict): Required parameters to look for master key attack.
            decryption_key_params (dict): Required parameters to look for a decryption attack.
            corruptable_vars_MK (list): The list of corruptable variables involved in the master key attack (if any).
            corruptable_vars_DK (list): The list of corruptable variables involved in the decryption attack (if any).
            security_analysis_params (dict): The required parameters to perform a security analysis of the scheme.


        Returns:
            (bool): If the inputs are valid e.g. corruption models and variable type are correct.
        """

        is_init_correct = True

        self.corruptable_vars_MK = corruptable_vars_MK
        self.corruptable_vars_DK = corruptable_vars_DK

        if security_analysis_params:
            security_attack = SecurityAttack()
            security_attack.init(
                security_analysis_params["key"],
                security_analysis_params["k_encodings"],
                security_analysis_params["c_encodings"],
                security_analysis_params["mpk_encodings"],
                security_analysis_params["unknown"],
            )

            # update unknown variables array with list of corruptable vars

            for elem in security_analysis_params["corruptable_vars"]:
                security_attack.add_corruptable_variable_generic(elem)

            self.analysis_list.append(security_attack)

        if master_key_params:
            master_key_attack = MasterKeyAttack()

            if master_key_params["corruption_model"] != "NoCorruption":
                master_key_attack.SOL_MSG = (
                    "[*] Master key attack with corruption found: "
                )
                master_key_attack.NOT_FOUND_MSG = (
                    "[!] No Master key attack with corruption found"
                )
            else:
                master_key_attack.SOL_MSG = "[*] Master key attack found: "
                master_key_attack.NOT_FOUND_MSG = "[!] No Master key attack found. "

            master_key_attack.init(
                master_key_params["masterkey"],
                master_key_params["keyenco"],
                master_key_params["unknown"],
            )

            match str(master_key_params["corruption_model"]):
                case "NoCorruption":
                    master_key_attack.set_corruption_model(
                        MasterKeyCorruptionModel.NoCorruption
                    )
                case "CA":
                    master_key_attack.set_corruption_model(MasterKeyCorruptionModel.CA)
                case "AA":
                    master_key_attack.set_corruption_model(MasterKeyCorruptionModel.AA)
                case "mixed_CA_corr":
                    master_key_attack.set_corruption_model(
                        MasterKeyCorruptionModel.mixed_CA
                    )
                case "mixed_AA_corr":
                    master_key_attack.set_corruption_model(
                        MasterKeyCorruptionModel.mixed_AA
                    )
                case _:
                    is_init_correct = False

            for elem in master_key_params["MPK_CA"]:
                master_key_attack.add_mpk_CA(elem)

            for elem in master_key_params["MPK_AA"]:
                master_key_attack.add_mpk_AA(elem)

            for elem in master_key_params["MPK_vars"]:
                master_key_attack.add_mpk(elem)

            for elem in master_key_params["GP_vars"]:
                master_key_attack.add_gp_variable(elem)

            if self.corruptable_vars_MK is not None:
                for var in self.corruptable_vars_MK:
                    if "type" in var:
                        if "var" in var:
                            if str(var["type"]) in [
                                "MPK_CA",
                                "MSK_CA",
                                "MPK_AA",
                                "MSK_AA",
                            ]:
                                match str(var["type"]):
                                    case "MPK_CA":
                                        master_key_attack.add_corruptable_var(
                                            MasterKeyCorruptedVariable.MPK_CA,
                                            parse_expr(var["var"]),
                                        )
                                    case "MSK_CA":
                                        master_key_attack.add_corruptable_var(
                                            MasterKeyCorruptedVariable.MSK_CA,
                                            parse_expr(var["var"]),
                                        )
                                    case "MPK_AA":
                                        master_key_attack.add_corruptable_var(
                                            MasterKeyCorruptedVariable.MPK_AA,
                                            parse_expr(var["var"]),
                                        )
                                    case "MSK_AA":
                                        master_key_attack.add_corruptable_var(
                                            MasterKeyCorruptedVariable.MSK_AA,
                                            parse_expr(var["var"]),
                                        )
                                    case _:
                                        is_init_correct = False

            self.analysis_list.append(master_key_attack)

        if decryption_key_params:
            decryption_attack = DecryptionAttack()
            decryption_attack.init(
                decryption_key_params["key"],
                decryption_key_params["k_encodings"],
                decryption_key_params["c_encodings"],
                decryption_key_params["mpk_encodings"],
                decryption_key_params["gp_encodings"],
                decryption_key_params["unknown"],
            )

            match str(decryption_key_params["corruption_model"]):
                case "NoCorruption":
                    decryption_attack.set_corruption_model(
                        DecryptionKeyCorruptionModel.NoCorruption
                    )
                case "AA":
                    decryption_attack.set_corruption_model(
                        DecryptionKeyCorruptionModel.AA
                    )
                case "AA_extended":
                    decryption_attack.set_corruption_model(
                        DecryptionKeyCorruptionModel.AA_extended
                    )
                case _:
                    is_init_correct = False

            for elem in decryption_key_params["MPK_AAi"]:
                decryption_attack.add_mpk_AAi(elem)

            for elem in decryption_key_params["MPK_AAj"]:
                decryption_attack.add_mpk_AAj(elem)

            for elem in decryption_key_params["misc_vars"]:
                decryption_attack.add_misc(elem)

            if self.corruptable_vars_DK is not None:
                for var in self.corruptable_vars_DK:
                    if "type" in var:
                        if "var" in var:
                            if str(var["type"]) in ["MPK_AAi", "MSK_AAi", "misc"]:
                                match str(var["type"]):
                                    case "MPK_AAi":
                                        decryption_attack.add_corruptable_var(
                                            DecryptionKeyCorruptedVariable.MPK_AAi,
                                            parse_expr(var["var"]),
                                        )
                                    case "MSK_AAi":
                                        decryption_attack.add_corruptable_var(
                                            DecryptionKeyCorruptedVariable.MSK_AAi,
                                            parse_expr(var["var"]),
                                        )
                                    case "misc":
                                        decryption_attack.add_corruptable_var(
                                            DecryptionKeyCorruptedVariable.misc,
                                            parse_expr(var["var"]),
                                        )
                                    case _:
                                        is_init_correct = False

            self.analysis_list.append(decryption_attack)

        return is_init_correct

    def run(self) -> None:
        """
        For those analysis with sufficient parameters, it runs them.
        """
        for attack in self.analysis_list:
            if attack.enabled == True:
                attack.run()

    def run_logic(self) -> None:
        """
        For those analysis with sufficient parameters, it runs them.
        However, it only tries to find attacks whenever the security
        analysis fails.
        """

        print("[*] Starting complete analysis")

        for attack in self.analysis_list:
            if attack.enabled == True:
                if attack.description == "SecurityAttack":
                    print("[*] Security analysys")
                    attack.run()

        if not (attack.trivial_secure or attack.collusion_secure):
            print("[*] Looking for attacks...")
            for attack in self.analysis_list:
                if attack.enabled == True:
                    if attack.description == "MasterKeyAttack":
                        attack.run()
                    if attack.description == "DecryptionAttack":
                        attack.run()
        else:
            for attack in self.analysis_list:
                if attack.enabled == True:
                    if attack.description == "MasterKeyAttack":
                        attack.enabled = False
                    if attack.description == "DecryptionAttack":
                        attack.enabled = False

    def show_solution(self) -> list:
        """
        Returns the results of the performed analysis.

        Returns:
            solution (list): The results obtained.
            proof_data (list):
        """

        proof_data = None
        proof_header = None

        for attack in self.analysis_list:
            if attack.enabled == True:
                match attack.description:
                    case "SecurityAttack":
                        print("\n[*] Security analysis results:\n")
                        self.sol_list.append("sec_placeholder")
                        self.sol_list.append(attack.show_solution())
                        print("\n" + attack.show_solution())
                        attack.show_proof()
                        proof_data, proof_header = attack.show_proof_latex()
                    case "MasterKeyAttack":
                        print("\n[*] Master key attack results:\n")
                        attack.format_encodings()
                        print("\n" + attack.show_solution())
                        self.sol_list.append("mk_placeholder")
                        self.sol_list.append(attack.format_encodings_string())
                        self.sol_list.append(attack.show_solution())
                    case "DecryptionAttack":
                        print("\n[*] Decryption key attack results:\n")
                        attack.format_encodings()
                        print("\n" + attack.show_solution())
                        self.sol_list.append("da_placeholder")
                        self.sol_list.append(attack.format_encodings_string())
                        self.sol_list.append(attack.show_solution())
                    case _:
                        pass  # TODO: catch error

        return self.sol_list, proof_data, proof_header

    def is_scheme_fractional(self) -> bool:
        """
        If there is a security analysis attached, it
        returns if the ABE scheme is fractional or not.

        Returns:
            (bool): Is the scheme fractional ?
        """

        for attack in self.analysis_list:
            if attack.enabled == True:
                if attack.description == "SecurityAttack":
                    return attack.is_fractional

        return False

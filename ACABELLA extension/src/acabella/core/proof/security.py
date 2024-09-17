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

from acabella.core.common.utils import *
from acabella.core.cryptanalysis.attack import Attack
from acabella.core.proof.security_analysis_ac17 import *
from acabella.core.proof.trivial_security_and_collusion import (
    analysis_trivial_and_collusion_security,
)
from acabella.core.proof.ac17_correctness_checks import *

import sympy as sp

init_printing(use_unicode=True)


class SecurityAttack(Attack):
    """
    Analyzes the security of an ABE scheme.

    Attributes:
        SOL_MSG (str): The scheme is secure.
        NOT_FOUND_MSG (str): The scheme is insecure.
        alpha (sp.core.list.Symbol): Representation of the master key.
        s (sp.core.list.Symbol): Representation of the blinding factor.
        key (sp.core.list.Symbol): Representation of the master key and blinding factor.
        is_fractional (bool): The scheme is fractional.
        sol (string): Solution of the attack, if found.
        k_encodings (list): List of sp.core.symbol.Symbol types representing the key
            encodings.
        c_encodings (list): List of sp.core.symbol.Symbol types representing the
            ciphertext components.
        mpk_encodings (list): List of sp.core.symbol.Symbol types representing the
            master public key components involved in the attack (they could be related
            to corruption of the authorities).
        unknown (list): List of sp.core.symbol.Symbol types representing the
            unknown variables.
        trivial_secure (bool): The scheme is trivial secure.
        collusion_secure (bool): The scheme is collusion secure.
    """

    SOL_MSG = "[*] The scheme is secure: "
    NOT_FOUND_MSG = "[!] The scheme is insecure"
    alpha = None
    s = None
    is_fractional = None
    sol = None
    k_encodings = None
    c_encodings = None
    key = None
    mpk_encodings = None
    unknown = None
    trivial_secure = False
    collusion_secure = False
    description = "SecurityAttack"
    result_security = None
    proof_log = None

    def init(self, key, k_encodings, c_encodings, mpk_encodings, unknown) -> None:
        # self.alpha = alpha
        # self.s = s
        self.key = key
        # self.is_fractional =  is_fractional
        self.sol = None
        self.k_encodings = k_encodings
        self.c_encodings = c_encodings
        self.mpk_encodings = mpk_encodings
        self.unknown = unknown
        self.trivial_secure = False
        self.collusion_secure = False
        self.result_security = None
        self.proof_log = None

    def __init__(self) -> None:
        """
        The constructor for SecurityAttack class.
        """
        self.alpha = None
        self.s = None
        self.key = None
        self.is_fractional = None
        self.sol = None
        self.k_encodings = None
        self.c_encodings = None
        self.mpk_encodings = None
        self.unknown = None
        self.trivial_secure = False
        self.collusion_secure = False
        self.result_security = None
        self.proof_log = None

    def show_solution(self) -> str:
        """
        Returns the result of the attack.

        Returns:
            solution (str): The result of the attack.
        """
        return self.sol

    def show_proof(self) -> None:
        """
        Returns the result of the proof.
        """
        # process proof log

        placeholder_1 = "\n The selective proof: \n"
        placeholder_2 = "\n The co-selective proof: \n"

        if self.proof_log:
            for line in self.proof_log:
                if self.proof_log[self.proof_log.index(line) - 1] == placeholder_1:
                    pprint(line, use_unicode=True)
                elif self.proof_log[self.proof_log.index(line) - 1] == placeholder_2:
                    pprint(line, use_unicode=True)
                else:
                    print(line)

    def show_proof_latex(self) -> None:
        """
        Returns the result of the proof in latex for HTML.

        """

        message_log = []
        header = []
        post_header = False

        # process proof log

        placeholder_1 = "\n The selective proof: \n"
        placeholder_2 = "\n The co-selective proof: \n"

        if self.proof_log:
            for line in self.proof_log:
                if line == placeholder_1:
                    break
                else:
                    header.append(line)

        message_log.append(placeholder_1)

        if self.proof_log:
            for line in self.proof_log:
                if self.proof_log[self.proof_log.index(line) - 1] == placeholder_1:
                    post_header = True
                    message_log.append("\[ " + latex(line) + " \]")
                elif self.proof_log[self.proof_log.index(line) - 1] == placeholder_2:
                    message_log.append("\[ " + latex(line) + " \]")
                else:
                    if post_header:
                        message_log.append(line)

        if self.proof_log:
            return "\n".join(message_log), "\n".join(header)
        else:
            return None, None

    def format_encodings(self) -> None:
        """
        Prints the involved encodings in the given ABE scheme.
        """
        # TODO

    def set_sol_msg(self, msg: str) -> None:
        """
        Allows to set the found solution message.

        Parameters:
            msg (str): Message.
        """
        self.SOL_MSG = msg

    def set_not_found_msg(self, msg: str) -> None:
        """
        Allows to set the not found solution message.

        Parameters:
            msg (str): Message.
        """
        self.NOT_FOUND_MSG = msg

    def run(self) -> None:
        """
        Analyze the security of the scheme with the supplied
        ABE scheme parameters.
        """

        # First, we determine the type of scheme.
        is_fractional = not all_enc_contains_no_fractions(
            self.k_encodings, self.c_encodings, self.unknown
        )
        self.is_fractional = is_fractional

        if not is_fractional:

            # Second, we need to determine alpha and special s.
            res, alpha, special_s = blinding_value_correct_form(
                self.key,
                self.k_encodings,
                self.c_encodings,
                self.mpk_encodings,
                self.unknown,
            )

            print("res: ", res)
            print("alpha: ", alpha)
            print("special_s: ", special_s)

            if res:
                (
                    self.trivial_secure,
                    self.collusion_secure,
                    self.result_security,
                    self.proof_log,
                ) = security_analysis(
                    alpha,
                    special_s,
                    self.k_encodings,
                    self.c_encodings,
                    self.mpk_encodings,
                    self.unknown,
                    [],
                    [],
                )
            else:
                self.trivial_secure, self.collusion_secure, self.result_security = (
                    analysis_trivial_and_collusion_security(
                        self.key,
                        self.k_encodings,
                        self.c_encodings,
                        self.mpk_encodings,
                        self.unknown,
                    )
                )
        else:
            self.trivial_secure, self.collusion_secure, self.result_security = (
                analysis_trivial_and_collusion_security(
                    self.key,
                    self.k_encodings,
                    self.c_encodings,
                    self.mpk_encodings,
                    self.unknown,
                )
            )

        self.sol = "NOTE: If the scheme is MA-ABE you might try to run this check with corruption.\n\n"
        self.sol += str(self.result_security)

    def add_corruptable_variable_generic(self, corr: sp.core.symbol.Symbol) -> None:
        """
        Adds variables that can be obtained by corruption to the unknown variables array.

        Parameters:
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.unknown is not None:
            self.unknown = list(filter((corr).__ne__, self.unknown))


class SecurityAttackVen23(Attack):
    """
    Analyzes the security of an ABE scheme.

    Attributes:
        SOL_MSG (str): The scheme is secure.
        NOT_FOUND_MSG (str): The scheme is insecure.
        alpha (sp.core.list.Symbol): Representation of the master key.
        s (sp.core.list.Symbol): Representation of the blinding factor.
        key (sp.core.list.Symbol): Representation of the master key and blinding factor.
        is_fractional (bool): The scheme is fractional.
        sol (string): Solution of the attack, if found.
        k_encodings (list): List of sp.core.symbol.Symbol types representing the key
            encodings.
        c_encodings (list): List of sp.core.symbol.Symbol types representing the
            ciphertext components.
        mpk_encodings (list): List of sp.core.symbol.Symbol types representing the
            master public key components involved in the attack (they could be related
            to corruption of the authorities).
        unknown (list): List of sp.core.symbol.Symbol types representing the
            unknown variables.
        trivial_secure (bool): The scheme is trivial secure.
        collusion_secure (bool): The scheme is collusion secure.
    """

    SOL_MSG = "[*] The scheme is secure: "
    NOT_FOUND_MSG = "[!] The scheme is insecure"
    alpha = None
    s = None
    is_fractional = None
    sol = None
    k_encodings = None
    c_encodings = None
    key = None
    mpk_encodings = None
    unknown = None
    trivial_secure = False
    collusion_secure = False
    description = "SecurityAttack"
    result_security = None
    proof_log = None

    def init(
        self, CM, k_encodings, c_encodings, mpk_encodings, unknown, alpha, special_s
    ) -> None:
        # self.alpha = alpha
        # self.s = s
        self.CM = CM
        self.alpha = alpha
        self.special_s = special_s
        # self.is_fractional =  is_fractional
        self.sol = None
        self.k_encodings = k_encodings
        self.c_encodings = c_encodings
        self.mpk_encodings = mpk_encodings
        self.unknown = unknown
        self.trivial_secure = False
        self.collusion_secure = False
        self.result_security = None
        self.proof_log = None

    def __init__(self) -> None:
        """
        The constructor for SecurityAttack class.
        """
        self.alpha = None
        self.special_s = None
        self.CM = None
        self.is_fractional = None
        self.sol = None
        self.k_encodings = None
        self.c_encodings = None
        self.mpk_encodings = None
        self.unknown = None
        self.trivial_secure = False
        self.collusion_secure = False
        self.result_security = None
        self.proof_log = None

    def show_solution(self) -> str:
        """
        Returns the result of the attack.

        Returns:
            solution (str): The result of the attack.
        """
        return self.sol

    def show_proof(self) -> None:
        """
        Returns the result of the proof.
        """
        # process proof log

        placeholder_1 = "\n The selective proof: \n"
        placeholder_2 = "\n The co-selective proof: \n"

        if self.proof_log:
            for line in self.proof_log:
                if self.proof_log[self.proof_log.index(line) - 1] == placeholder_1:
                    pprint(line, use_unicode=True)
                elif self.proof_log[self.proof_log.index(line) - 1] == placeholder_2:
                    pprint(line, use_unicode=True)
                else:
                    print(line)

    def show_proof_latex(self) -> None:
        """
        Returns the result of the proof in latex for HTML.

        """

        message_log = []
        header = []
        post_header = False

        # process proof log

        placeholder_1 = "\n The selective proof: \n"
        placeholder_2 = "\n The co-selective proof: \n"

        if self.proof_log:
            for line in self.proof_log:
                if line == placeholder_1:
                    break
                else:
                    header.append(line)

        message_log.append(placeholder_1)

        if self.proof_log:
            for line in self.proof_log:
                if self.proof_log[self.proof_log.index(line) - 1] == placeholder_1:
                    post_header = True
                    message_log.append("\[ " + latex(line) + " \]")
                elif self.proof_log[self.proof_log.index(line) - 1] == placeholder_2:
                    message_log.append("\[ " + latex(line) + " \]")
                else:
                    if post_header:
                        message_log.append(line)

        if self.proof_log:
            return "\n".join(message_log), "\n".join(header)
        else:
            return None, None

    def format_encodings(self) -> None:
        """
        Prints the involved encodings in the given ABE scheme.
        """
        # TODO

    def set_sol_msg(self, msg: str) -> None:
        """
        Allows to set the found solution message.

        Parameters:
            msg (str): Message.
        """
        self.SOL_MSG = msg

    def set_not_found_msg(self, msg: str) -> None:
        """
        Allows to set the not found solution message.

        Parameters:
            msg (str): Message.
        """
        self.NOT_FOUND_MSG = msg

    def run(self) -> None:

        print("ven23 run")
        """
            Analyze the security of the scheme with the supplied
            ABE scheme parameters.
            """

        # First, we determine the type of scheme.
        is_fractional = not all_enc_contains_no_fractions(
            self.k_encodings, self.c_encodings, self.unknown
        )
        self.is_fractional = is_fractional

        if not is_fractional:

            # Second, we need to determine alpha and special s.
            # res, alpha, special_s = blinding_value_correct_form(self.key, self.k_encodings, self.c_encodings, self.mpk_encodings, self.unknown)

            # print("res: ", res)
            # print("alpha: ", alpha)
            # print("special_s: ", special_s)

            (
                self.trivial_secure,
                self.collusion_secure,
                self.result_security,
                self.proof_log,
            ) = security_analysis_ven23(
                self.alpha,
                self.special_s,
                self.k_encodings,
                self.c_encodings,
                self.mpk_encodings,
                self.unknown,
                [],
                [],
            )
        else:
            self.sol = "GPES schemes are not in fractional form.\n\n"

        self.sol = "NOTE: If the scheme is MA-ABE you might try to run this check with corruption.\n\n"
        self.sol += str(self.result_security)

    def add_corruptable_variable_generic(self, corr: sp.core.symbol.Symbol) -> None:
        """
        Adds variables that can be obtained by corruption to the unknown variables array.

        Parameters:
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.unknown is not None:
            self.unknown = list(filter((corr).__ne__, self.unknown))


# TODO[ISABELLA]
class SecurityAttackISABELLA(Attack):
    """
    Analyzes the security of an ABE scheme.

    Attributes:
        SOL_MSG (str): The scheme is secure.
        NOT_FOUND_MSG (str): The scheme is insecure.
        alpha (sp.core.list.Symbol): Representation of the master key.
        s (sp.core.list.Symbol): Representation of the blinding factor.
        key (sp.core.list.Symbol): Representation of the master key and blinding factor.
        is_fractional (bool): The scheme is fractional.
        sol (string): Solution of the attack, if found.
        k_encodings (list): List of sp.core.symbol.Symbol types representing the key
            encodings.
        c_encodings (list): List of sp.core.symbol.Symbol types representing the
            ciphertext components.
        mpk_encodings (list): List of sp.core.symbol.Symbol types representing the
            master public key components involved in the attack (they could be related
            to corruption of the authorities).
        unknown (list): List of sp.core.symbol.Symbol types representing the
            unknown variables.
        trivial_secure (bool): The scheme is trivial secure.
        collusion_secure (bool): The scheme is collusion secure.
    """

    SOL_MSG = "[*] The scheme is secure: "
    NOT_FOUND_MSG = "[!] The scheme is insecure"
    alpha = None
    s = None
    is_fractional = None
    sol = None
    k_encodings = None
    c_encodings = None
    key = None
    mpk_encodings = None
    unknown = None
    trivial_secure = False
    collusion_secure = False
    description = "SecurityAttack"
    result_security = None
    proof_log = None

    def init(
        self, CM, k_encodings, c_encodings, mpk_encodings, unknown, alpha, special_s
    ) -> None:
        # self.alpha = alpha
        # self.s = s
        self.CM = CM
        self.alpha = alpha
        self.special_s = special_s
        # self.is_fractional =  is_fractional
        self.sol = None
        self.k_encodings = k_encodings
        self.c_encodings = c_encodings
        self.mpk_encodings = mpk_encodings
        self.unknown = unknown
        self.trivial_secure = False
        self.collusion_secure = False
        self.result_security = None
        self.proof_log = None

    def __init__(self) -> None:
        """
        The constructor for SecurityAttack class.
        """
        self.alpha = None
        self.special_s = None
        self.CM = None
        self.is_fractional = None
        self.sol = None
        self.k_encodings = None
        self.c_encodings = None
        self.mpk_encodings = None
        self.unknown = None
        self.trivial_secure = False
        self.collusion_secure = False
        self.result_security = None
        self.proof_log = None

    def show_solution(self) -> str:
        """
        Returns the result of the attack.

        Returns:
            solution (str): The result of the attack.
        """
        return self.sol

    def show_proof(self) -> None:
        """
        Returns the result of the proof.
        """
        # process proof log

        placeholder_1 = "\n The selective proof: \n"
        placeholder_2 = "\n The co-selective proof: \n"

        if self.proof_log:
            for line in self.proof_log:
                if self.proof_log[self.proof_log.index(line) - 1] == placeholder_1:
                    pprint(line, use_unicode=True)
                elif self.proof_log[self.proof_log.index(line) - 1] == placeholder_2:
                    pprint(line, use_unicode=True)
                else:
                    print(line)

    def show_proof_latex(self) -> None:
        """
        Returns the result of the proof in latex for HTML.

        """

        message_log = []
        header = []
        post_header = False

        # process proof log

        placeholder_1 = "\n The selective proof: \n"
        placeholder_2 = "\n The co-selective proof: \n"

        if self.proof_log:
            for line in self.proof_log:
                if line == placeholder_1:
                    break
                else:
                    header.append(line)

        message_log.append(placeholder_1)

        if self.proof_log:
            for line in self.proof_log:
                if self.proof_log[self.proof_log.index(line) - 1] == placeholder_1:
                    post_header = True
                    message_log.append("\[ " + latex(line) + " \]")
                elif self.proof_log[self.proof_log.index(line) - 1] == placeholder_2:
                    message_log.append("\[ " + latex(line) + " \]")
                else:
                    if post_header:
                        message_log.append(line)

        if self.proof_log:
            return "\n".join(message_log), "\n".join(header)
        else:
            return None, None

    def format_encodings(self) -> None:
        """
        Prints the involved encodings in the given ABE scheme.
        """
        # TODO

    def set_sol_msg(self, msg: str) -> None:
        """
        Allows to set the found solution message.

        Parameters:
            msg (str): Message.
        """
        self.SOL_MSG = msg

    def set_not_found_msg(self, msg: str) -> None:
        """
        Allows to set the not found solution message.

        Parameters:
            msg (str): Message.
        """
        self.NOT_FOUND_MSG = msg

    def run(self) -> None:

        print("ven23 run")
        """
            Analyze the security of the scheme with the supplied
            ABE scheme parameters.
            """

        # First, we determine the type of scheme.
        is_fractional = not all_enc_contains_no_fractions(
            self.k_encodings, self.c_encodings, self.unknown
        )
        self.is_fractional = is_fractional

        if not is_fractional:

            # Second, we need to determine alpha and special s.
            # res, alpha, special_s = blinding_value_correct_form(self.key, self.k_encodings, self.c_encodings, self.mpk_encodings, self.unknown)

            # print("res: ", res)
            # print("alpha: ", alpha)
            # print("special_s: ", special_s)

            (
                self.trivial_secure,
                self.collusion_secure,
                self.result_security,
                self.proof_log,
            ) = security_analysis_ven23(
                self.alpha,
                self.special_s,
                self.k_encodings,
                self.c_encodings,
                self.mpk_encodings,
                self.unknown,
                [],
                [],
            )
        else:
            self.sol = "GPES schemes are not in fractional form.\n\n"

        self.sol = "NOTE: If the scheme is MA-ABE you might try to run this check with corruption.\n\n"
        self.sol += str(self.result_security)

    def add_corruptable_variable_generic(self, corr: sp.core.symbol.Symbol) -> None:
        """
        Adds variables that can be obtained by corruption to the unknown variables array.

        Parameters:
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.unknown is not None:
            self.unknown = list(filter((corr).__ne__, self.unknown))

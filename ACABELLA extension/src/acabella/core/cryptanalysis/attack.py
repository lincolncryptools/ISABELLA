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

"""attack.py: Abstract class with format_solution method"""

from sympy import *

init_printing(use_unicode=True)

DEBUG = False


class Attack:
    """
    Base class for performing attacks.

    Attributes:
        enabled (bool): The attack is enabled.
        description (str): Description of the attack.
    """

    enabled = True
    description = None

    def format_solution(
        self, encoding_list: list, solution_list: list, msg: str
    ) -> str:
        """
        Given the solution of an attack e.g. if it has found an attack and the
        description of the ABE scheme, it formats the output to be presented
        to the user.

        Parameters:
            encoding_list (list): Descrition of the scheme encodings.
            solution_list (sp.core.list.Symbol): Result of the attack.
            msg (str): Base message to present to the user.

        Returns:
            Result of the attack (str): Well built string describing the attack result.
        """
        assert len(encoding_list) == len(
            solution_list
        ), "format_solution: mismatch in encoding and solution lists"

        mul_list = [
            simplify(Symbol(str(a)) * Symbol(str(b)))
            for a, b in zip(encoding_list, solution_list)
            if b != 0
        ]

        if DEBUG:
            print(encoding_list)
            print(solution_list)

        return msg + " + ".join("{}".format(e) for e in mul_list)

    def init(self) -> None:
        """
        Initialization function of the attack.
        """
        pass

    def run(self) -> None:
        """
        Function for running the attack.
        """
        pass

    def show_solution(self) -> None:
        """
        Shows the result of the attack.
        """
        pass

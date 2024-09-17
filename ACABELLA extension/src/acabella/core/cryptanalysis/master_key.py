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
from acabella.core.cryptanalysis.decryption import DecryptionAttack

import copy
from enum import Enum
import sympy as sp


class MasterKeyCorruptionModel(Enum):
    """
    Allowed corruption models in master key attacks.

    Attributes:
        NoCorruption (int): Corruption is not possible.
        CA (int): Corruption of the Central Authority (CA).
        AA (int): Simple corruption of the Attribute Authority (AA).
        mixed_CA (int): CA/CAs and AAs are involved. However only CA/CAs are corruptable.
        mixed_AA (int): CA/CAs and AAs are involved. However only AAs are corruptable.
    """

    NoCorruption = 1
    CA = 2
    AA = 3
    mixed_CA = 4
    mixed_AA = 5


class MasterKeyCorruptedVariable(Enum):
    """
    Describes the origin of corruptable variables in master key attacks.

    Attributes:
        MPK_CA (int): The variable is part of the corruption of the Central Authority (CA).
        MPK_AA (int): The variable belongs to an Attribute Authority j. It will be used to obtain the master key of an AA[i].
    """

    MPK_CA = 1
    MPK_AA = 2


class MasterKeyAttack(Attack):
    """
    Finds master key attacks in ABE schemes, optionally
    assuming the corruption of Central Authorities (CAs)
    and Attribute Authorities (AAs).

    Attributes:
        SOL_MSG (str): Message to report if a master key attack is found.
        NOT_FOUND_MSG (str): Message to report if a master key attack is not found.
        corr_model (str): Corruption model involved in the attack.
        masterkey (sp.core.symbol.Symbol): Master key to recover.
        keyenco(list): Key encodings as a list of sp.core.symbol.Symbol elements. Each
            element, k_i, is related to a key encoding involved in the attack. However, we
            must note that it can be related to a mpk element or to a gp element.
        unknown(list): List of unknown elements (sp.core.symbol.Symbol). These are the elements
            that in theory unknown for the attacker. However, they can be disclosed by corrupting
            an authority for instance.
        solution(str): Solution of the attack, if found.
        description(str): Description of the attack, by default MasterKeyAttack.
        c(list): List of ciphertext encodings. Not used.
        mpk(list): List of mpk related variables.
        gp(list): List of global parameter related variables.
        translation_table(list): List of mappings variable -> mpk or variable -> gp to improve
            the details of an attack when printing the solution.
        MPK_CA(list): List of mpk variables that belong to the CA.
        MSK_CA(list): List of msk variables that belong to the CA.
        MPK_AA(list): List of mpk variables that belong to the AA.
        MSK_AA(list): List of msk variables that belong to the AA.
    """

    SOL_MSG = "[*] Master key attack found: "
    NOT_FOUND_MSG = "[!] No Master key attack found"
    corr_model = MasterKeyCorruptionModel.NoCorruption
    masterkey = None
    keyenco = None
    unknown = None
    solution = None
    description = "MasterKeyAttack"
    c = []
    mpk = []
    gp = []
    translation_table = []

    # for output improvement
    # in corruption cases

    MPK_CA = []
    MSK_CA = []
    MPK_AA = []
    MSK_AA = []

    # utilized for keeping track of the type
    # of variables that enters the attack
    # via corruption of CA or AA

    # a corruption map contains dictionary entries
    # of the form {"name", "origin"} where origins
    # corresponds to one of the entries of the
    # `MasterKeyCorruptedVariable enumeration

    corruption_map = []

    def __init__(self) -> None:
        """
        The constructor for MasterKeyAttack class.
        """
        self.masterkey = None
        self.keyenco = None

        # master key attacks relies on the
        # decryption key attack class
        # we save in keyenco_mk the original
        # encoding that initialized the master
        # key attack
        self.keyenco_mk = None

        self.unknown = None
        self.solution = None
        self.description = "MasterKeyAttack"

        self.c = []
        self.mpk = []
        self.gp = []
        self.translation_table = []

        self.MPK_CA = []
        self.MSK_CA = []
        self.MPK_AA = []
        self.MSK_AA = []

        self.corruption_map = []

    def init(self, masterkey: list, keyenco: list, unknown: list) -> None:
        """
        Initializes a master key attack based on:

        Parameters:
            masterkey (list): The master key to find.
            keyenco (list): The key encodings.
            unknown (list): The list of not known variables of the ABE scheme.
        """
        self.masterkey = masterkey
        self.keyenco = keyenco
        self.unknown = unknown

    def run(self) -> None:
        """
        Tries to find a master key attack on the given ABE scheme.
        It reuses the implementation of the decryption attack with the
        flag master_key_attack_only set as True.
        """
        decryption_attack = DecryptionAttack()

        self.keyenco = self.gen_dict(self.keyenco)

        # save encodings here before passing them
        # to decryption class. It will be used for
        # printing pourposes in format_encodings
        self.keyenco_mk = copy.deepcopy(self.keyenco)

        decryption_attack.init(
            self.masterkey,
            self.keyenco,
            self.c,
            self.mpk,
            self.gp,
            self.unknown,
            master_key_attack_only=True,
        )
        decryption_attack.set_sol_msg(self.SOL_MSG)
        decryption_attack.set_not_found_msg(self.NOT_FOUND_MSG)

        decryption_attack.run()
        self.solution = decryption_attack.show_solution()

    def format_encodings(self) -> None:
        """
        Prints the involved encodings in the given ABE scheme.
        """

        if self.keyenco_mk:
            print("\nList of encodings:")
            for elem in self.keyenco_mk:
                print("\t", elem["dsc"], ":", elem["op"])

        # Give details about the corruption model in relation to the
        # attack

        if self.corr_model == MasterKeyCorruptionModel.mixed_AA:
            print(
                "\nFor the corruption of an attribute authority AA[j] and attacking an attribute authority AA[i]."
            )

        if self.corr_model == MasterKeyCorruptionModel.CA:
            print("\nFor the corruption of the Central Authority.")

        if self.corr_model == MasterKeyCorruptionModel.mixed_CA:
            print(
                "\nFor the corruption of a Central Authority [i] in a model with several Attribute Authorities [j]."
            )

        if self.translation_table:
            dict_index = 0
            print("\nInformation on additional encodings:")
            for elem in self.translation_table:
                print(f'\t[*] {elem["name"]} corresponds to {elem["type"]}{dict_index}')
                dict_index = dict_index + 1
            print(
                "\nNOTE: Global parameters gp[i] are added to the matrix as key encodings and could appear as k[i] elements."
            )

        # Print the contents of the master key pairs according to the
        # corruption model:

        if self.MPK_AA or self.MSK_AA or self.MPK_CA or self.MSK_CA:

            print("\nStructure of CA/AAs:")

            match self.corr_model:
                case MasterKeyCorruptionModel.NoCorruption:
                    print(f"\tContents of the CA MPK encodings: {self.MPK_CA}")
                    print(f"\tContents of the AA MPK encodings: {self.MPK_AA}")
                case MasterKeyCorruptionModel.CA:
                    print(f"\tContents of the CA MPK encodings: {self.MPK_CA}")
                case MasterKeyCorruptionModel.AA:
                    print(f"\tContents of the AA MPK encodings: {self.MPK_AA}")
                case MasterKeyCorruptionModel.mixed_CA:
                    print(f"\tContents of the CA MPK encodings: {self.MPK_CA}")
                    print(f"\tContents of the AA MPK encodings: {self.MPK_AA}")
                case MasterKeyCorruptionModel.mixed_AA:
                    print(f"\tContents of the CA MPK encodings: {self.MPK_CA}")
                    print(f"\tContents of the AA MPK encodings: {self.MPK_AA}")
                case _:
                    pass

        # Print corruption map

        if self.corr_model != MasterKeyCorruptionModel.NoCorruption:
            if self.corr_model == MasterKeyCorruptionModel.mixed_AA:
                print("\nList of variables obtained via the corruption of AA[j]:")
            else:
                print("\nList of variables obtained via corruption:")
            for elem in self.corruption_map:
                print(f'\t{elem["name"]} from {elem["origin"]}')

    def format_encodings_string(self) -> str:
        """
        Return a string with the involved encodings in the given ABE scheme.
        """

        ret_string = []

        if self.keyenco_mk:
            ret_string.append("\nList of encodings:")
            for elem in self.keyenco_mk:
                ret_string.append("\t " + str(elem["dsc"]) + " : " + str(elem["op"]))

        # Give details about the corruption model in relation to the
        # attack

        if self.corr_model == MasterKeyCorruptionModel.mixed_AA:
            ret_string.append(
                "\nFor the corruption of an attribute authority AA[j] and attacking an attribute authority AA[i]."
            )

        if self.corr_model == MasterKeyCorruptionModel.CA:
            ret_string.append("\nFor the corruption of the Central Authority.")

        if self.corr_model == MasterKeyCorruptionModel.mixed_CA:
            ret_string.append(
                "\nFor the corruption of a Central Authority [i] in a model with several Attribute Authorities [j]."
            )

        if self.translation_table:
            dict_index = 0
            ret_string.append("\nInformation on additional encodings:")
            for elem in self.translation_table:
                ret_string.append(
                    f'\t[*] {elem["name"]} corresponds to {elem["type"]}{dict_index}'
                )
                dict_index = dict_index + 1
            ret_string.append(
                "\nNOTE: Global parameters gp[i] are added to the matrix as key encodings and could appear as k[i] elements."
            )

        # Print the contents of the master key pairs according to the
        # corruption model:

        if self.MPK_AA or self.MSK_AA or self.MPK_CA or self.MSK_CA:

            ret_string.append("\nStructure of CA/AAs:\n")

            match self.corr_model:
                case MasterKeyCorruptionModel.NoCorruption:
                    ret_string.append(
                        f"\tContents of the CA MPK encodings: {self.MPK_CA}"
                    )
                    ret_string.append(
                        f"\tContents of the AA MPK encodings: {self.MPK_AA}"
                    )
                case MasterKeyCorruptionModel.CA:
                    ret_string.append(
                        f"\tContents of the CA MPK encodings: {self.MPK_CA}"
                    )
                case MasterKeyCorruptionModel.AA:
                    ret_string.append(
                        f"\tContents of the AA MPK encodings: {self.MPK_AA}"
                    )
                case MasterKeyCorruptionModel.mixed_CA:
                    ret_string.append(
                        f"\tContents of the CA MPK encodings: {self.MPK_CA}"
                    )
                    ret_string.append(
                        f"\tContents of the AA MPK encodings: {self.MPK_AA}"
                    )
                case MasterKeyCorruptionModel.mixed_AA:
                    ret_string.append(
                        f"\tContents of the CA MPK encodings: {self.MPK_CA}"
                    )
                    ret_string.append(
                        f"\tContents of the AA MPK encodings: {self.MPK_AA}"
                    )
                case _:
                    pass

        # Print corruption map

        if self.corr_model != MasterKeyCorruptionModel.NoCorruption:
            if self.corr_model == MasterKeyCorruptionModel.mixed_AA:
                ret_string.append(
                    "\nList of variables obtained via the corruption of AA[j]:"
                )
            else:
                ret_string.append("\nList of variables obtained via corruption:")
            for elem in self.corruption_map:
                ret_string.append(f'\t{elem["name"]} from {elem["origin"]}')

        return "\n".join(ret_string)

    def show_solution(self) -> str:
        """
        Returns the result of the attack.

        Returns:
            solution (str): The result of the attack.
        """
        return "\n" + self.solution + "\n"

    def add_corruptable_var(
        self, origin: MasterKeyCorruptedVariable, corr: sp.core.symbol.Symbol
    ) -> None:
        """
        Adds a corruptable var from the master pair of CA or AA.
        Then, calls either add_corruptable_variable_from_CA or
        add_corruptable_variable_from_AA accordingly.
        Finally, it adds an entry to the corruption map (`self.corruption_map`)

        Parameters:
            origin (MasterKeyCorruptedVariable): MSK/MPK_CA or MSK/PK_AA (Enum)
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """

        # ensure origin belongs to MSK/MPK_CA or MSK/MPK_AA

        corr_belongs = (
            corr in self.MPK_CA
            or corr in self.MPK_AA
            or corr in self.MSK_CA
            or corr in self.MSK_AA
        )
        entry = None

        if corr_belongs:
            match origin:
                case MasterKeyCorruptedVariable.MPK_CA:
                    self.add_corruptable_variable_generic(corr)
                    entry = {"name": corr, "origin": "MPK_CA"}

                case MasterKeyCorruptedVariable.MPK_AA:
                    self.add_corruptable_variable_generic(corr)
                    entry = {"name": corr, "origin": "MPK_AA"}

                case _:
                    print(f"Origin in MasterKeyCorruptedVariable not defined")

            if entry is not None:
                self.corruption_map.append(entry)

    def add_corruptable_variable_generic(self, corr: sp.core.symbol.Symbol) -> None:
        """
        Adds CA variables that can be obtained by corruption.

        Parameters:
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.unknown is not None:
            self.unknown = list(filter((corr).__ne__, self.unknown))

    def add_gp_variable(self, gpv: sp.core.symbol.Symbol) -> None:
        """
        Adds a global parameter to the attack.

        Parameters:
            gpv (symbol): global parameter variable.
        """
        if self.keyenco is not None:
            self.keyenco.append(gpv)

        # add entry to translation table

        table_entry = {"name": gpv.name, "type": "gp"}
        self.translation_table.append(table_entry)

    def add_mpk(self, mpkv: sp.core.symbol.Symbol) -> None:
        """
        Adds a master public key to the attack.

        Parameters:
            mpkv (sp.core.symbol.Symbol): mpk variable.
        """

        if self.keyenco is not None:
            self.keyenco.append(mpkv)

        # add entry to translation table

        if self.corr_model == (
            MasterKeyCorruptionModel.mixed_CA or MasterKeyCorruptionModel.mixed_AA
        ):
            table_entry = {"name": mpkv.name, "type": "mpk_i_j"}
        else:
            table_entry = {"name": mpkv.name, "type": "mpk"}

        self.translation_table.append(table_entry)

    def add_mpk_CA(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Adds a CA master public key.

        Parameters:
            elem (sp.core.symbol.Symbol): mpk CA variable.
        """
        self.MPK_CA.append(elem)

    def add_msk_CA(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Adds a CA master secret key.

        Parameters:
            elem (sp.core.symbol.Symbol): msk CA variable.
        """
        self.MSK_CA.append(elem)

    def add_mpk_AA(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Adds an AA master public key.

        Parameters:
            elem (sp.core.symbol.Symbol): mpk AA variable.
        """
        self.MPK_AA.append(elem)

    def add_msk_AA(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Adds an AA master secret key.

        Parameters:
            elem (sp.core.symbol.Symbol): msk AA variable.
        """
        self.MSK_AA.append(elem)

    def set_corruption_model(self, corr_m) -> None:
        """
        Sets the corruption model involved in the attack. By
        the default the corruption model is MasterKeyCorruptionModel.NoCorruption.

        Parameters:
            corr_m (MasterKeyCorruptionModel): Corruption model.
        """
        self.corr_model = corr_m

    def gen_dict(self, k: list) -> list:
        """
        Generates an annotated dictionary based on the encodings
        of the given ABE scheme:

        Parameters:
            k (list): Key encodings of the ABE scheme.

        Returns:
            Annotated dictionary (list): Annotated dictionary of the ABE scheme with descriptions.
        """

        if (
            self.corr_model == MasterKeyCorruptionModel.mixed_AA
            or self.corr_model == MasterKeyCorruptionModel.mixed_CA
        ):
            all_k = []
            for i in k:
                if self.corr_model == MasterKeyCorruptionModel.mixed_CA:
                    entry = {"op": i, "dsc": "k" + str(k.index(i)) + "[i][j]"}
                else:
                    entry = {"op": i, "dsc": "k" + str(k.index(i)) + "[i]"}

                for e in self.translation_table:
                    if str(i) == e["name"]:
                        entry["dsc"] = e["type"]  # + str(k.index(i))

                all_k.append(entry)
        else:
            all_k = []
            for i in k:
                entry = {"op": i, "dsc": "k" + str(k.index(i))}
                all_k.append(entry)

        return all_k

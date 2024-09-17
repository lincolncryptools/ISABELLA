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

from enum import Enum
import sympy as sp

init_printing(use_unicode=True)


class DecryptionKeyCorruptedVariable(Enum):
    """
    Describes the origin of corruptable variables in decryption key attacks.

    Attributes:
        MPK_AAi (int): MPK of an attribute authority [i].
        misc (int): misc. variable part of an attribute autority [i].
    """

    MPK_AAi = 1
    misc = 2


class DecryptionKeyCorruptionModel(Enum):
    """
    Allowed corruption models in decryption key attacks.

    Attributes:
        NoCorruption (int): Corruption is not possible.
        AA (int): Corruption of one Attribute Authority (AA[i]).
        AA_extended (int): Corruption of the Attribute Authority (AA[i]) where
            the interaction with a second Attribute Authority AA[j] is required.
            This interaction means that a second attribute-independent ciphertext
            is generated from a second authority.
    """

    NoCorruption = 1
    AA = 2
    AA_extended = 3


class DecryptionAttack(Attack):
    """
    Finds master key attacks in ABE schemes, optionally
    assuming the corruption of the central authority (CA).

    Attributes:
        SOL_MSG (str): Message to report if a decryption key attack is found.
        NOT_FOUND_MSG (str): Message to report if a decryption key attack is not found.
        corr_model (int): Corruption model involved in the attack.
        key (sp.core.symbol.Symbol): Key to recover.
        all_p(list): All the possible combinations of the supplied encodings (of type
            sp.core.symbol.Symbol) related to key, ciphertext, global parameters and master public key components.
        unknown(list): List of variables (of type sp.core.symbol.Symbol) that are
            supposed to be unknown to the attacker.
        sol(string): Solution of the attack, if found.
        k_encodings(list): List of sp.core.symbol.Symbol types representing the key
            encodings.
        c_encodings(list): List of sp.core.symbol.Symbol types representing the
            ciphertext components.
        mpk_encodings(list): List of sp.core.symbol.Symbol types representing the
            master public key components involved in the attack (they could be related
            to corruption of the authorities).
        gp_encodings(list): List of sp.core.symbol.Symbol types representing the
            global parameter components involved in the attack (they could be related
            to corruption of the authorities).
    """

    SOL_MSG = "[*] Decryption attack found: "
    NOT_FOUND_MSG = "[!] No decryption attack found"
    corr_model = DecryptionKeyCorruptionModel.NoCorruption
    key = None
    all_p = None
    unknown = None
    sol = None
    k_encodings = None
    c_encodings = None
    mpk_encodings = None
    gp_encodings = None
    is_master_key_attack = False

    MPK_AAi = []
    MSK_AAi = []
    MPK_AAj = []
    MSK_AAj = []
    misc = []

    # utilized for keeping track of the type
    # of variables that enters the attack
    # via corruption of CA or AA

    # a corruption map contains dictionary entries
    # of the form {"name", "origin"} where origins
    # corresponds to one of the entries of the
    # `DecryptionKeyCorruptedVariable enumeration

    corruption_map = []

    def init(
        self,
        key,
        k_encodings,
        c_encodings,
        mpk_encodings,
        gp_encodings,
        unknown,
        master_key_attack_only=False,
    ) -> None:
        self.key = key
        self.unknown = unknown
        self.description = "DecryptionAttack"

        self.k_encodings = k_encodings
        self.c_encodings = c_encodings
        self.mpk_encodings = mpk_encodings
        self.gp_encodings = gp_encodings
        self.is_master_key_attack = master_key_attack_only

        if master_key_attack_only == False:
            self.all_p = self.gen_all_p_ex_dict(
                self.k_encodings,
                self.c_encodings,
                self.mpk_encodings,
                self.gp_encodings,
            )
        else:
            self.all_p = self.k_encodings

    def __init__(self) -> None:
        """
        The constructor for DecryptionAttack class.
        """
        self.key = None
        self.all_p = None
        self.unknown = None
        self.sol = None
        self.k_encodings = None
        self.c_encodings = None
        self.mpk_encodings = None
        self.gp_encodings = None
        self.is_master_key_attack = False

        self.MPK_AAi = []
        self.MSK_AAi = []
        self.MPK_AAj = []
        self.MSK_AAj = []

        self.misc = []

        self.corruption_map = []

    def show_solution(self) -> str:
        """
        Returns the result of the attack.

        Returns:
            solution (str): The result of the attack.
        """
        return "\n" + self.sol + "\n"

    def format_encodings(self) -> None:
        """
        Prints the involved encodings in the given ABE scheme.
        """
        if self.all_p:
            print("List of encodings:")
            for elem in self.all_p:
                print("\t", elem["dsc"], ":", elem["op"])

        if self.k_encodings:
            for elem in self.k_encodings:
                if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
                    print(
                        "\t", "k" + "[i]" + str(self.k_encodings.index(elem)), ":", elem
                    )
                else:
                    print("\t", "k" + str(self.k_encodings.index(elem)), ":", elem)

        if self.c_encodings:
            for elem in self.c_encodings:
                print("\t", "c" + str(self.c_encodings.index(elem)), ":", elem)

        if self.mpk_encodings:
            for elem in self.mpk_encodings:
                print("\t", "mpk" + str(self.mpk_encodings.index(elem)), ":", elem)

        if self.gp_encodings:
            for elem in self.gp_encodings:
                print("\t", "gp" + str(self.gp_encodings.index(elem)), ":", elem)

        # Give details about the corruption model in relation to the
        # attack

        if self.corr_model == DecryptionKeyCorruptionModel.AA:
            print("\nFor the corruption of an attribute authority AA[i].")

        if self.corr_model == DecryptionKeyCorruptionModel.AA_extended:
            print(
                "\nFor the corruption of an attribute authority AA[i] where c0 and c1 are obtained from different attribute authorities."
            )

        # Print the contents of the master key pairs according to the
        # corruption model:

        if self.MPK_AAi or self.MSK_AAi or self.MPK_AAj or self.MSK_AAj:

            print("\nStructure of CA/AAs:")

            match self.corr_model:
                case DecryptionKeyCorruptionModel.AA:
                    print(f"\tMaster key pair of AA[i]: mpk[i]: {self.MPK_AAi}")
                case DecryptionKeyCorruptionModel.AA_extended:
                    print(f"\tMaster key pair of AA[i]: mpk[i]: {self.MPK_AAi}")
                    print(f"\tMaster key pair of AA[j]: mpk[j]: {self.MPK_AAj}")
                case _:
                    pass

        # Print corruption map

        if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
            print("\nList of variables obtained via corruption:")
            for elem in self.corruption_map:
                print(f'\t{elem["name"]} from {elem["origin"]}')

    def format_encodings_string(self) -> str:
        """
        Return a string with the involved encodings in the given ABE scheme.
        """

        ret_string = []

        if self.all_p:
            ret_string.append("List of encodings:")
            for elem in self.all_p:
                ret_string.append("\t " + str(elem["dsc"]) + " : " + str(elem["op"]))

        if self.k_encodings:
            for elem in self.k_encodings:
                if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
                    ret_string.append(
                        "\t"
                        + " k"
                        + "[i]"
                        + str(self.k_encodings.index(elem))
                        + " : "
                        + str(elem)
                    )
                else:
                    ret_string.append(
                        "\t"
                        + "k"
                        + str(self.k_encodings.index(elem))
                        + " : "
                        + str(elem)
                    )

        if self.c_encodings:
            for elem in self.c_encodings:
                ret_string.append(
                    "\t" + "c" + str(self.c_encodings.index(elem)) + " : " + str(elem)
                )

        if self.mpk_encodings:
            for elem in self.mpk_encodings:
                ret_string.append(
                    "\t"
                    + "mpk"
                    + str(self.mpk_encodings.index(elem))
                    + " : "
                    + str(elem)
                )

        if self.gp_encodings:
            for elem in self.gp_encodings:
                ret_string.append(
                    "\t" + "gp" + str(self.gp_encodings.index(elem)) + " : " + str(elem)
                )

        # Give details about the corruption model in relation to the
        # attack

        if self.corr_model == DecryptionKeyCorruptionModel.AA:
            ret_string.append("\nFor the corruption of an attribute authority AA[i].")

        if self.corr_model == DecryptionKeyCorruptionModel.AA_extended:
            ret_string.append(
                "\nFor the corruption of an attribute authority AA[i] where c0 and c1 are obtained from different attribute authorities."
            )

        # Print the contents of the master key pairs according to the
        # corruption model:

        if self.MPK_AAi or self.MSK_AAi or self.MPK_AAj or self.MSK_AAj:

            ret_string.append("\nStructure of CA/AAs:")

            match self.corr_model:
                case DecryptionKeyCorruptionModel.AA:
                    ret_string.append(
                        f"\tMaster key pair of AA[i]: mpk[i]: {self.MPK_AAi}"
                    )
                case DecryptionKeyCorruptionModel.AA_extended:
                    ret_string.append(
                        f"\tMaster key pair of AA[i]: mpk[i]: {self.MPK_AAi}"
                    )
                    ret_string.append(
                        f"\tMaster key pair of AA[j]: mpk[j]: {self.MPK_AAj}"
                    )
                case _:
                    pass

        # Print corruption map

        if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
            ret_string.append("\nList of variables obtained via corruption:")
            for elem in self.corruption_map:
                ret_string.append(f'\t{elem["name"]} from {elem["origin"]}')

        return "\n".join(ret_string)

    def add_corruptable_var_generic(self, corr: sp.core.symbol.Symbol):
        """
        Adds CA variables that can be obtained by corruption.

        Parameters:
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.unknown is not None:
            self.unknown = list(filter((corr).__ne__, self.unknown))

        if self.is_master_key_attack == False:
            self.all_p = self.gen_all_p_ex_dict(
                self.k_encodings,
                self.c_encodings,
                self.mpk_encodings,
                self.gp_encodings,
            )
        else:
            self.all_p = self.k_encodings

    def add_mpk_variable(self, mpkv: sp.core.symbol.Symbol):
        """
        Adds mpk variables that could be obtained by corruption.

        Parameters:
            mpkv (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.mpk_encodings is not None:
            self.mpk_encodings.append(mpkv)

        # regenerate encodings

        self.all_p = self.gen_all_p_ex_dict(
            self.k_encodings, self.c_encodings, self.mpk_encodings, self.gp_encodings
        )

    def add_gp_variable(self, gpv: list):
        """
        Adds gp variables that could be obtained by corruption.

        Parameters:
            gpv (sp.core.symbol.Symbol): Corruptable variable.
        """
        if self.gp_encodings is not None:
            self.gp_encodings.append(gpv)

        # regenerate encodings

        self.all_p = self.gen_all_p_ex_dict(
            self.k_encodings, self.c_encodings, self.mpk_encodings, self.gp_encodings
        )

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

    def transform_encoding_list(self, denomprod, p):
        """
        Function that 'normalizes' the encodings
        (by multiplying everything with the product of
        denominators^2 (because each element in p is paired already))
        (master key is multiplied by the product^2).

        Parameters:
            denomprod (sp.core.symbol.Symbo): product of denominators.
             p (list): list of all possible combinations between the encodings.
        """
        pcpy = []

        for pp in p:
            pcpy.append(cancel(pp * denomprod))

        return canonical(pcpy)

    def decryption_attack_generalized_alt(self, masterkey, p, unknown):
        """
        Tries to find a decryption attack in the supplied parameters of
        a particular ABE scheme.

        Parameters:
            masterkey (sp.core.symbol.Symbo): Master key to find.
            p (list): list of all possible combinations between the encodings (sp.core.symbol.Symbo).
            unkonwn (list): list of unkown components for the attacker (sp.core.symbol.Symbo).
        """
        p = canonical(p)

        # function to select all denoms
        denoms = collect_denoms(p, unknown)
        denomprod = denoms_prod(denoms)

        # function that 'normalizes' the encodings
        # (by multiplying everything with the product of
        # denominators**2 (because each element in p is paired already))
        # (master key is multiplied by the product**2)
        p = self.transform_encoding_list(denomprod**2, p)
        masterkey = canonical([cancel(masterkey * denomprod**2)])[0]

        (mat, uvector) = writeencodingasprod(p, unknown)
        # could run either of the following lines - using 'new' here for certainty
        # (mat,uvector) = reordermatuvec_new(masterkey,mat,uvector)
        # (mat, uvector) = reorder_mat_uvec_with_alpha(masterkey, mat, uvector)

        m1 = mat
        m2 = uvector

        m1_m = Matrix(mat)
        m2_m = Matrix(uvector)

        mat = Matrix(mat)

        # attack target_vector
        # use here the function from find_solution or something
        luvec1 = len(uvector)
        target_vector = Matrix([writepolyasprod(masterkey, uvector, unknown)])
        luvec2 = len(uvector)
        if luvec1 != luvec2:
            return False, None, None, None

        mat2 = mat.row_insert(shape(mat)[0], target_vector)

        ## testing code
        # """
        (mat2, uvector, lis_del_rows, lis_del_cols) = trim_matrix_and_uvector(
            mat2, uvector
        )
        m2_m = Matrix(uvector)

        for ind in lis_del_cols:
            target_vector.col_del(ind)
            m1_m.col_del(ind)

        for ind in lis_del_rows:
            del self.all_p[ind]
            m1_m.row_del(ind)
        # """
        ## testing code

        ns = mat2.transpose().nullspace()

        matns = Matrix([v.transpose() for v in ns])

        err, f_sol = find_attack_row(matns)
        if err:
            return False, None, None, None

        n_l = shape(m2_m)[0]
        n_d = shape(mat)[1]
        check_v = zeros(1, n_l)

        for i in range(0, len(f_sol)):
            check_v += f_sol[i] * mat2.row(i)

        ctr = 0
        for ind in check_v:
            check_v[ctr] = cancel(check_v[ctr])
            ctr += 1

        m1 = m1_m.tolist()
        m2 = m2_m.tolist()

        if check_v == target_vector:
            return True, m1, m2, f_sol
        else:
            return False, None, None, None

    # version of the super_matrix algorithm with
    # decryption_attack_generalized

    def run(self) -> None:
        """
        Tries to find a decryption attack with the supplied
        ABE scheme parameters.
        """
        op = [a_dict["op"] for a_dict in self.all_p]
        dsc = [a_dict["dsc"] for a_dict in self.all_p]

        result, m, v, sol = self.decryption_attack_generalized_alt(
            self.key, op, self.unknown
        )
        if result == True:
            dsc = [a_dict["dsc"] for a_dict in self.all_p]
            self.sol = super().format_solution(dsc, sol, self.SOL_MSG)
        else:
            self.sol = self.NOT_FOUND_MSG

    def set_corruption_model(self, corr_m) -> None:
        """
        Sets the corruption model involved in the attack. By
        the default the corruption model is DecryptionKeyCorruptionModel.NoCorruption.

        Parameters:
            corr_m (DecryptionKeyCorruptionModel): Corruption model.
        """
        self.corr_model = corr_m

    def gen_all_p_ex_dict(self, k: list, c: list, mpk: list, gp: list) -> list:
        """
        Generates all the possible combinations given key, ciphertext, mpk
        and global parameter related encodings.

        Parameters:
            k (list): Key encodings of type sp.core.symbol.Symbol.
            c (list): Ciphertext encodings of type sp.core.symbol.Symbol.
            mpk (list): mpk encodings of type sp.core.symbol.Symbol.
            gp (list): gp encodings of type sp.core.symbol.Symbol.
        """

        # k*c

        all_k_c = []
        for i in k:
            for j in c:
                if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
                    entry = {
                        "op": i * j,
                        "dsc": "k" + str(k.index(i)) + "[i]" + "*c" + str(c.index(j)),
                    }
                else:
                    entry = {
                        "op": i * j,
                        "dsc": "k" + str(k.index(i)) + "*c" + str(c.index(j)),
                    }

                all_k_c.append(entry)

        # k*mpk

        all_k_mpk = []
        for i in k:
            for j in mpk:
                if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
                    entry = {
                        "op": i * j,
                        "dsc": "k"
                        + str(k.index(i))
                        + "[i]"
                        + "*mpk"
                        + str(mpk.index(j)),
                    }
                else:
                    entry = {
                        "op": i * j,
                        "dsc": "k" + str(k.index(i)) + "*mpk" + str(mpk.index(j)),
                    }
                all_k_mpk.append(entry)

        # c*mpk

        all_mpk_c = []
        for i in c:
            for j in mpk:
                entry = {
                    "op": i * j,
                    "dsc": "c" + str(c.index(i)) + "*mpk" + str(mpk.index(j)),
                }
                all_mpk_c.append(entry)

        # c*gp

        all_gp_c = []
        for i in c:
            for j in gp:
                entry = {
                    "op": i * j,
                    "dsc": "c" + str(c.index(i)) + "*gp" + str(gp.index(j)),
                }
                all_gp_c.append(entry)

        # k*gp

        all_gp_k = []
        for i in k:
            for j in gp:
                if self.corr_model != DecryptionKeyCorruptionModel.NoCorruption:
                    entry = {
                        "op": i * j,
                        "dsc": "k" + str(k.index(i)) + "[i]" + "*gp" + str(gp.index(j)),
                    }
                else:
                    entry = {
                        "op": i * j,
                        "dsc": "k" + str(k.index(i)) + "*gp" + str(gp.index(j)),
                    }
                all_gp_k.append(entry)

        return all_k_c + all_k_mpk + all_mpk_c + all_gp_c + all_gp_k

    def add_corruptable_var(
        self, origin: DecryptionKeyCorruptionModel, corr: sp.core.symbol.Symbol
    ) -> None:
        """
        Adds a corruptable var from the master pair of a AA[i]
        or another related variable obtained via corruption.
        Then, it calls the correspondent function.
        Finally, it adds an entry to the corruption map (`self.corruption_map`)

        Parameters:
            origin (DecryptionKeyCorruptedVariable): MSK/MPK_AAi or misc(Enum)
            corr (sp.core.symbol.Symbol): Corruptable variable.
        """

        # ensure origin belongs to possible values

        corr_belongs = corr in self.MPK_AAi or corr in self.misc
        entry = None

        if corr_belongs:
            match origin:
                case DecryptionKeyCorruptedVariable.MPK_AAi:
                    self.add_corruptable_var_generic(corr)
                    entry = {"name": corr, "origin": "MPK_AAi"}

                case DecryptionKeyCorruptedVariable.misc:
                    self.add_corruptable_var_generic(corr)
                    entry = {"name": corr, "origin": "AAi"}

                case _:
                    print(f"Origin in DecryptionKeyCorruptedVariable not defined")

            if entry is not None:
                self.corruption_map.append(entry)

    def add_mpk_AAi(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Describes the structure of AAi in the AA_extended corruption
        model. It is related to the encoding of MPK_i, for the
        corrupted A_i authority.

        Parameters:
            elem (sp.core.symbol.Symbol): mpk AA variable.
        """
        self.MPK_AAi.append(elem)

    def add_mpk_AAj(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Describes the structure of AAj in the AA_extended corruption
        model. It is related to the encoding of MPK_j, for the
        honest A_j authority.

        Parameters:
            elem (sp.core.symbol.Symbol): mpk AA variable.
        """
        self.MPK_AAj.append(elem)

    def add_misc(self, elem: sp.core.symbol.Symbol) -> None:
        """
        Adds an AA master secret key.

        Parameters:
            elem (sp.core.symbol.Symbol): msk AA variable.
        """
        self.misc.append(elem)

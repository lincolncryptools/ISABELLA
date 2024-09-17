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


"""conditional.py: Conditional decryption attack based on the Venema-Alpar framework"""

from acabella.core.common.utils import *
from sympy import *
from acabella.core.cryptanalysis.attack import Attack
from acabella.core.common.encodings import *
from acabella.core.common.access_structures import *
from acabella.core.cryptanalysis.decryption import DecryptionAttack

init_printing(use_unicode=True)


class ConditionalDecryptionAttack(Attack):
    """
    It looks for conditional decryption attacks in the
    provided ABE scheme.

    Attributes:
        SOL_MSG (str): Default found attack string.
        NOT_FOUND_MSG (str): Default not found attack string.
    """

    SOL_MSG = "[*] Conditional decryption attack found: "
    NOT_FOUND_MSG = "[!] No conditional decryption attack found"

    def init(
        self,
        masterkey,
        special_s,
        benc,
        kenc_fixed,
        kenc_att,
        cenc_fixed,
        cenc_att,
        unknown,
        prefixes,
        nr_indexed_encodings,
    ) -> None:
        """
        Initializes the conditional decryption attack class with the description
        of the ABE scheme.

        Parameters:
            masterkey (list): The master key to find.
            special_s (list): The blinding value.
            benc (list): The list of b encodings.
            kenc_fixed (list): List of fixed key encodings.
            kenc_att (list): List of key encodings related to attributes.
            cenc_fixed (list): List of ciphertext encodings.
            cenc_att (list): List of ciphertext encodings related to attributes.
            unknown (list): List of unknown variables.
            prefixes (list): List of prefixes.
            nr_indexed_encodings (list): Number of indexed encodings.
            description (list): Description of the attack.
        """
        self.masterkey = masterkey
        self.special_s = special_s
        self.benc = benc
        self.kenc_fixed = kenc_fixed
        self.kenc_att = kenc_att
        self.cenc_fixed = cenc_fixed
        self.cenc_att = cenc_att
        self.unknown = unknown
        self.prefixes = prefixes
        self.nr_indexed_encodings = nr_indexed_encodings

        self.description = "ConditionalDecryptionAttack"

    def __init__(self) -> None:
        self.masterkey = None
        self.special_s = None
        self.benc = None
        self.kenc_fixed = None
        self.kenc_att = None
        self.cenc_fixed = None
        self.cenc_att = None
        self.unknown = None
        self.prefixes = None
        self.nr_indexed_encodings = None
        self.description = None

    def show_solution(self):
        """
        Returns the result of the attack.
        """
        return self.sol

    def set_sol_msg(self, msg: str) -> None:
        """
        Sets the solution found default message.

        Parameters:
            msg (str): Message.
        """
        self.SOL_MSG = msg

    def set_not_found_msg(self, msg: str) -> None:
        """
        Sets the solution not found default message.

        Parameters:
            msg (str): Message.
        """
        self.NOT_FOUND_MSG = msg

    def try_all_conditional_decryption_attacks(self) -> list:
        """
        Looks for conditional decryption attacks.
        """
        att_range_key_1 = [1]
        att_range_key_2 = [2]
        att_range_ct = [1, 2]

        self.benc = create_b_encoding([], self.benc, [1, 2])
        cenc = create_ciphertext_encoding(
            self.cenc_fixed,
            self.cenc_att,
            self.special_s,
            att_range_ct,
            self.prefixes,
            self.nr_indexed_encodings,
        )

        kenc_init = create_key_encoding(
            self.kenc_fixed,
            self.kenc_att,
            att_range_key_1,
            self.prefixes,
            self.nr_indexed_encodings,
            [1],
        )
        unknown2 = generate_unknown_variable_set(
            kenc_init, cenc, self.benc, att_range_ct, att_range_key_1 + att_range_key_2
        )
        self.unknown = merge_lists(self.unknown, unknown2)

        (_, uvectork) = writeencodingasprod(kenc_init, self.unknown)
        max_nr_of_keys = len(uvectork)

        msg = []
        first_attack = True

        for nr_of_keys in range(1, max_nr_of_keys):
            key_indices1 = [i for i in range(1, nr_of_keys + 1)]
            key_indices2 = [i + nr_of_keys for i in key_indices1]

            kenc = create_key_encoding(
                self.kenc_fixed,
                self.kenc_att,
                att_range_key_1,
                self.prefixes,
                self.nr_indexed_encodings,
                key_indices1,
            )
            kenc += create_key_encoding(
                self.kenc_fixed,
                self.kenc_att,
                att_range_key_2,
                self.prefixes,
                self.nr_indexed_encodings,
                key_indices2,
            )

            unknown2 = generate_unknown_variable_set(
                kenc, cenc, self.benc, att_range_ct, att_range_key_1 + att_range_key_2
            )
            self.unknown = merge_lists(self.unknown, unknown2)

            decryption_attack = DecryptionAttack()
            decryption_attack.SOL_MSG = self.SOL_MSG
            decryption_attack.NOT_FOUND_MSG = self.NOT_FOUND_MSG
            decryption_attack.init(
                self.masterkey * self.special_s, kenc, cenc, self.benc, [], self.unknown
            )
            decryption_attack.run()

            if first_attack:
                msg.append(decryption_attack.show_solution())
                first_attack = False

        return msg

    def run(self) -> None:
        """
        Run the attack and initializes the result string
        for the user.
        """

        msg = self.try_all_conditional_decryption_attacks()
        if msg:
            self.sol = msg
        else:
            self.sol = self.NOT_FOUND_MSG


if __name__ == "__main__":

    # JLWW13

    alpha, b, bp, b0, b1, r, rp, r1, r2, r1p, r2p, x, y, s, sp = symbols(
        "alpha, b, bp, b0, b1, r, rp, r1, r2, r1p, r2p, x, y, s, sp"
    )

    # these are fixed in the system
    att_mpk_group = parse_expr("att_mpk_group")
    att_scalar = parse_expr("att_scalar")
    policy_share = parse_expr("lambda_policy_share")

    k_fixed_1 = alpha + r
    k_att_1 = r + get_indexed_encoding("rp", 1) * att_mpk_group
    k_att_2 = get_indexed_encoding("rp", 1)
    c_att_1 = policy_share * att_mpk_group
    c_att_2 = policy_share
    mpk1 = att_mpk_group
    special_s = s

    k_fixed = [k_fixed_1]
    k_att = [k_att_1, k_att_2]
    c_fixed = []
    c_att = [c_att_1, c_att_2]
    mpk = []

    prefixes = ["rp"]
    nr_indexed_encodings = 1

    cd_attack = ConditionalDecryptionAttack()
    cd_attack.init(
        alpha,
        special_s,
        mpk,
        k_fixed,
        k_att,
        c_fixed,
        c_att,
        [alpha, r, s],
        prefixes,
        nr_indexed_encodings,
    )
    cd_attack.run()
    print(cd_attack.show_solution())

    """
    # keeping this in for continuity
    
    key_indices1 = [1]
    att_range_key_1 = [1]
    key_indices2 = [2]
    att_range_key_2 = [2]
    att_range_ct = [1,2]
    
    benc = create_b_encoding([], mpk, [1,2])
    kenc = create_key_encoding(k_fixed, k_att, att_range_key_1, prefixes, nr_indexed_encodings, key_indices1)
    kenc += create_key_encoding(k_fixed, k_att, att_range_key_2, prefixes, nr_indexed_encodings, key_indices2)
    cenc = create_ciphertext_encoding(c_fixed, c_att, special_s, att_range_ct, prefixes, nr_indexed_encodings)

    unknown = generate_unknown_variable_set(kenc, cenc, benc)
            
    # this is the attack
    all_v = DecryptionAttack.gen_all_p_ex_dict(kenc, cenc, benc, [])                    
                                                                                   
    decryption_attack = DecryptionAttack()                                       
    decryption_attack.init(alpha * s, all_v, unknown)           
    decryption_attack.run()                                                      
    msg = decryption_attack.show_solution()  
    print(msg)
    """

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

from flask import Blueprint, flash, render_template, request

import json
from acabella.core.cryptanalysis.analysis import AnalysisWithCorruption
from acabella.core.common.parse_config import ParseConfig

bp = Blueprint("acabella_app", __name__)

# example attacks


@bp.route("/ndcw15_attack", methods=("GET", "POST"))
def ndcw15_attack():
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        select = request.form.get("analysis_select")

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not body:
            error = "JSON description of the ABE scheme is required."

        # if not select:
        #    error = "Analysis type is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(body)
            except ValueError as e:
                flash("The JSON description of the ABE scheme is not valid.")
                return render_template(
                    "acabella_app/ndcw15_attack.html",
                    analysis_type=[{"name": "Complete"}],
                )

            msg = None

            match str(select):
                case "Master key attack":
                    master_params, corruptable_vars = (
                        parse_config.generate_master_key_params()
                    )

                    if master_params is None:
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/ndcw15_attack.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(master_params, None, corruptable_vars, None, None)
                    analysis.run()
                    attack_result, _, _ = analysis.show_solution()
                    attack_result.pop(0)  # remove mk placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                    )  # posts)

                case "Decryption Attack":
                    dec_params, corruptable_vars = (
                        parse_config.generate_dec_key_params()
                    )

                    if dec_params is None:
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/ndcw15_attack.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(None, dec_params, None, corruptable_vars, None)
                    analysis.run()
                    attack_result, _, _ = analysis.show_solution()
                    attack_result.pop(0)  # remove mk placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                    )  # posts)

                case "Security":
                    security_params = parse_config.generate_security_analysis_params()

                    if security_params is None:
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/ndcw15_attack.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(None, None, None, None, security_params)
                    analysis.run()
                    attack_result, proof_result, proof_header = analysis.show_solution()

                    attack_result.pop(0)  # remove sec placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                        proof=proof_result,
                        proof_header=proof_header,
                    )  # posts)

                case "Complete":
                    (
                        security_params,
                        master_params,
                        corruptable_vars_master,
                        dec_params,
                        corruptable_vars_dec,
                    ) = parse_config.generate_all_params()

                    if (
                        security_params is None
                        or master_params is None
                        or dec_params is None
                    ):
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/ndcw15_attack.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(
                        master_params,
                        dec_params,
                        corruptable_vars_master,
                        corruptable_vars_dec,
                        security_params,
                    )

                    try:
                        analysis.run()
                    except:
                        flash(
                            "The analysis process found an error: The JSON input is not correct."
                        )
                        return render_template(
                            "acabella_app/ndcw15_attack.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    proof_result = None

                    attack_result, proof_result, proof_header = analysis.show_solution()

                    json_out = body

                    master_key_result = []
                    decryption_attack_result = []
                    sec_result = []

                    mk_start = False
                    da_start = False

                    # collect sec analysis

                    attack_result.pop(0)

                    for line in attack_result:
                        sec_result.append(line)
                        if line == "mk_placeholder":
                            sec_result.pop()
                            break

                    # collect mk analysis

                    for line in attack_result:
                        if mk_start:
                            master_key_result.append(line)
                        if line == "mk_placeholder":
                            mk_start = True
                        if line == "da_placeholder":
                            master_key_result.pop()
                            break

                    # collect da analysis

                    for line in attack_result:
                        if da_start:
                            decryption_attack_result.append(line)
                        if line == "da_placeholder":
                            da_start = True

                    return render_template(
                        "acabella_app/index.html",
                        master_key_result="\n".join(master_key_result),
                        decryption_attack_result="\n".join(decryption_attack_result),
                        is_complete="true",
                        json_out=json_out,
                        attack="\n".join(sec_result),
                        proof=proof_result,
                        proof_header=proof_header,
                    )  # posts)

                case _:
                    msg = "Incorrect analysis type"

    return render_template(
        "acabella_app/ndcw15_attack.html", analysis_type=[{"name": "Complete"}]
    )


@bp.route("/ksw08_attack", methods=("GET", "POST"))
def ksw08_attack():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template(
        "acabella_app/ksw08_attack.html", fractional=[{"name": "No"}]
    )


@bp.route("/cm14_attack", methods=("GET", "POST"))
def cm14_attack():

    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "decryption",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b", "s * b2"],
            "mpk": ["b"],
            "gp": [],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruption_model": "AA_extended",
            "corruptable_vars": [{"type": "MPK_AAi", "var": "b2"}],
            "MPK_AAi": ["b2"],
            "MPK_AAj": ["b"],
            "misc_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/cm14_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "AA_extended"}],
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/cm14_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "AA_extended"}],
            )

        default_entry["corruption_model"] = str(request.form.get("corruption_select"))
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash("The variables obtained via corruption are not correct.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["mpk_aai_vars"]:
            try:
                default_entry["MPK_AAi"] = json.loads(request.form["mpk_aai_vars"])
            except:
                flash("The contents of MPK_AAi are not correct.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["mpk_aaj_vars"]:
            try:
                default_entry["MPK_AAj"] = json.loads(request.form["mpk_aaj_vars"])
            except:
                flash("The contents of MPK_AAj are not correct.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["misc_vars"]:
            try:
                default_entry["misc_vars"] = json.loads(request.form["misc_vars"])
            except:
                flash("The description of the misc. vars is not correct.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["gp"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP vars is not correct.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

            dec_params, corruptable_vars = parse_config.generate_dec_key_params()
            if dec_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, dec_params, None, corruptable_vars, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/cm14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

            attack_result, _, _ = analysis.show_solution()

            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/cm14_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "AA_extended"}],
    )


@bp.route("/qlz13_attack", methods=("GET", "POST"))
def qlz13_attack():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        corruption_model = request.form.get("corruption_select")
        master_key = request.form["master_key"]
        unknown = request.form["unknown"]
        corr_vars = request.form["corr_vars"]

        mpk_ca_vars = request.form["mpk_ca_vars"]
        mpk_aa_vars = request.form["mpk_aa_vars"]
        mpk_vars = request.form["mpk_vars"]
        gp_vars = request.form["gp_vars"]

        default_entry = {
            "analysis": "master_key",
            "k": ["(alpha_i + r) / b", "r"],
            "master_key": "alpha_i",
            "unknown_vars": ["alpha_i", "r", "s"],
            "corruption_model": "AA",
            "corruptable_vars": [{"type": "MPK_AA", "var": "b"}],
            "MPK_CA": [],
            "MPK_AA": ["alpha_i", "b"],
            "MPK_vars": [],
            "GP_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/qlz13_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[
                    {"name": "No corruption"},
                    {"name": "CA"},
                    {"name": "AA"},
                    {"name": "Mixed CA"},
                    {"name": "Mixed AA"},
                ],
            )

        default_entry["corruption_model"] = (
            "NoCorruption"  # str(request.form.get('corruption_select'))
        )
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The description of the unknown variables is not correct.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash(
                    "The description of the variables obtained via corruption is not correct."
                )
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )
        else:
            default_entry["corruptable_vars"] = []

        if request.form["mpk_ca_vars"]:
            try:
                default_entry["MPK_CA"] = json.loads(request.form["mpk_ca_vars"])
            except:
                flash("The description of the CA MPK variables is not correct.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["mpk_aa_vars"]:
            try:
                default_entry["MPK_AA"] = json.loads(request.form["mpk_aa_vars"])
            except:
                flash("The description of the AA MPK variables is not correct.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["mpk_vars"]:
            try:
                default_entry["MPK_vars"] = json.loads(request.form["mpk_vars"])
            except:
                flash("The description of the MPK variables is not correct.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["GP_vars"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP variables is not correct.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

            master_params, corruptable_vars = parse_config.generate_master_key_params()
            if master_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(master_params, None, corruptable_vars, None, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/qlz13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

            attack_result, _, _ = analysis.show_solution()
            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/qlz13_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[
            {"name": "No corruption"},
            {"name": "CA"},
            {"name": "AA"},
            {"name": "Mixed CA"},
            {"name": "Mixed AA"},
        ],
    )


@bp.route("/")
def index():
    return render_template("acabella_app/index.html")


@bp.route("/process_json", methods=("GET", "POST"))
# @login_required
def process_json():
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        select = request.form.get("analysis_select")

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not body:
            error = "JSON description of the ABE scheme is required."

        # if not select:
        #    error = "Analysis type is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(body)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/process_json.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                )

            msg = None

            match str(select):
                case "Master key attack":
                    master_params, corruptable_vars = (
                        parse_config.generate_master_key_params()
                    )

                    if master_params is None:
                        flash("The JSON input is not valid.")
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(master_params, None, corruptable_vars, None, None)

                    try:
                        analysis.run()
                    except:
                        flash(
                            "The analysis process found an error: The JSON input is not correct."
                        )
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    attack_result, _, _ = analysis.show_solution()
                    attack_result.pop(0)  # remove mk placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        proof=None,
                        attack="\n".join(attack_result),
                    )  # posts)

                case "Decryption Attack":
                    dec_params, corruptable_vars = (
                        parse_config.generate_dec_key_params()
                    )

                    if dec_params is None:
                        flash("The JSON input is not valid.")
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(None, dec_params, None, corruptable_vars, None)

                    try:
                        analysis.run()
                    except:
                        flash(
                            "The analysis process found an error: The JSON input is not correct."
                        )
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    attack_result, _, _ = analysis.show_solution()
                    attack_result.pop(0)  # remove mk placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        proof=None,
                        attack="\n".join(attack_result),
                    )  # posts)

                case "Security":
                    security_params = parse_config.generate_security_analysis_params()

                    if security_params is None:
                        flash("The JSON input is not valid.")
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(None, None, None, None, security_params)

                    try:
                        analysis.run()
                    except:
                        flash(
                            "The analysis process found an error: The JSON input is not correct."
                        )
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    attack_result, proof_result, proof_header = analysis.show_solution()

                    attack_result.pop(0)  # remove sec placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                        proof=proof_result,
                        proof_header=proof_header,
                    )  # posts)
                case "Complete":
                    (
                        security_params,
                        master_params,
                        corruptable_vars_master,
                        dec_params,
                        corruptable_vars_dec,
                    ) = parse_config.generate_all_params()

                    if (
                        security_params is None
                        or master_params is None
                        or dec_params is None
                    ):
                        flash("The JSON input is not valid.")
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(
                        master_params,
                        dec_params,
                        corruptable_vars_master,
                        corruptable_vars_dec,
                        security_params,
                    )

                    try:
                        analysis.run()
                    except:
                        flash(
                            "The analysis process found an error: The JSON input is not correct."
                        )
                        return render_template(
                            "acabella_app/process_json.html",
                            analysis_type=[
                                {"name": "Master key attack"},
                                {"name": "Decryption Attack"},
                                {"name": "Complete"},
                                {"name": "Security"},
                            ],
                        )

                    attack_result, proof_result, proof_header = analysis.show_solution()

                    json_out = body

                    master_key_result = []
                    decryption_attack_result = []
                    sec_result = []

                    mk_start = False
                    da_start = False

                    # collect sec analysis

                    attack_result.pop(0)

                    for line in attack_result:
                        sec_result.append(line)
                        if line == "mk_placeholder":
                            sec_result.pop()
                            break

                    # collect mk analysis

                    for line in attack_result:
                        if mk_start:
                            master_key_result.append(line)
                        if line == "mk_placeholder":
                            mk_start = True
                        if line == "da_placeholder":
                            master_key_result.pop()
                            break

                    # collect da analysis

                    for line in attack_result:
                        if da_start:
                            decryption_attack_result.append(line)
                        if line == "da_placeholder":
                            da_start = True

                    return render_template(
                        "acabella_app/index.html",
                        master_key_result="\n".join(master_key_result),
                        decryption_attack_result="\n".join(decryption_attack_result),
                        is_complete="true",
                        json_out=json_out,
                        attack="\n".join(sec_result),
                        proof=proof_result,
                        proof_header=proof_header,
                    )  # posts)

                case _:
                    msg = "Incorrect analysis type"

    return render_template(
        "acabella_app/process_json.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
    )


@bp.route("/master_key", methods=("GET", "POST"))
# @login_required
def master_key():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        corruption_model = request.form.get("corruption_select")
        master_key = request.form["master_key"]
        unknown = request.form["unknown"]
        corr_vars = request.form["corr_vars"]

        mpk_ca_vars = request.form["mpk_ca_vars"]
        mpk_aa_vars = request.form["mpk_aa_vars"]
        mpk_vars = request.form["mpk_vars"]
        gp_vars = request.form["gp_vars"]

        default_entry = {
            "analysis": "master_key",
            "k": ["(alpha_i + r) / b", "r"],
            "master_key": "alpha_i",
            "unknown_vars": ["alpha_i", "r", "s"],
            "corruption_model": "AA",
            "corruptable_vars": [{"type": "MPK_AA", "var": "b"}],
            "MPK_CA": [],
            "MPK_AA": ["alpha_i", "b"],
            "MPK_vars": [],
            "GP_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/master_key.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[
                    {"name": "No corruption"},
                    {"name": "CA"},
                    {"name": "AA"},
                    {"name": "Mixed CA"},
                    {"name": "Mixed AA"},
                ],
            )

        match str(request.form.get("corruption_select")):
            case "No corruption":
                default_entry["corruption_model"] = "NoCorruption"
            case "CA":
                default_entry["corruption_model"] = "CA"
            case "AA":
                default_entry["corruption_model"] = "AA"
            case "Mixed CA":
                default_entry["corruption_model"] = "mixed_CA"
            case "Mixed AA":
                default_entry["corruption_model"] = "mixed_AA"
            case _:
                default_entry["corruption_model"] = "NoCorruption"

        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The key unknown variables description is not correct.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash(
                    "The description of the variables obtained via corruption is not correct."
                )
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )
        else:
            default_entry["corruptable_vars"] = []

        if request.form["mpk_ca_vars"]:
            try:
                default_entry["MPK_CA"] = json.loads(request.form["mpk_ca_vars"])
            except:
                flash("The description of the MPK CA variables is not correct.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["mpk_aa_vars"]:
            try:
                default_entry["MPK_AA"] = json.loads(request.form["mpk_aa_vars"])
            except:
                flash("The description of the MPK AA variables is not correct.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["mpk_vars"]:
            try:
                default_entry["MPK_vars"] = json.loads(request.form["mpk_vars"])
            except:
                flash("The description of the MPK variables is not correct.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["GP_vars"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP variables is not correct.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

            master_params, corruptable_vars = parse_config.generate_master_key_params()

            if master_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(master_params, None, corruptable_vars, None, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/master_key.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "CA"},
                        {"name": "AA"},
                        {"name": "Mixed CA"},
                        {"name": "Mixed AA"},
                    ],
                )

            attack_result, _, _ = analysis.show_solution()
            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/master_key.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[
            {"name": "No corruption"},
            {"name": "CA"},
            {"name": "AA"},
            {"name": "Mixed CA"},
            {"name": "Mixed AA"},
        ],
    )


@bp.route("/dec", methods=("GET", "POST"))
# @login_required
def dec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "decryption",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b", "s * b2"],
            "mpk": ["b"],
            "gp": [],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruption_model": "AA_extended",
            "corruptable_vars": [{"type": "MPK_AAi", "var": "b2"}],
            "MPK_AAi": ["b2"],
            "MPK_AAj": ["b"],
            "misc_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/dec.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[
                    {"name": "No corruption"},
                    {"name": "AA"},
                    {"name": "AA_extended"},
                ],
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/dec.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[
                    {"name": "No corruption"},
                    {"name": "AA"},
                    {"name": "AA_extended"},
                ],
            )

        default_entry["corruption_model"] = str(request.form.get("corruption_select"))
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash("The variables obtained via corruption are not correct.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )
        else:
            default_entry["corruptable_vars"] = []

        if request.form["mpk_aai_vars"]:
            try:
                default_entry["MPK_AAi"] = json.loads(request.form["mpk_aai_vars"])
            except:
                flash("The MPK_AAi variables are not correct.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

        if request.form["mpk_aaj_vars"]:
            try:
                default_entry["MPK_AAj"] = json.loads(request.form["mpk_aaj_vars"])
            except:
                flash("The MPK_AAj variables are not correct.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

        if request.form["misc_vars"]:
            try:
                default_entry["misc_vars"] = json.loads(request.form["misc_vars"])
            except:
                flash("The misc variables are not correct.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["gp"] = json.loads(request.form["gp_vars"])
            except:
                flash("The GP variables are not correct.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

            dec_params, corruptable_vars = parse_config.generate_dec_key_params()

            if dec_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, dec_params, None, corruptable_vars, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/dec.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[
                        {"name": "No corruption"},
                        {"name": "AA"},
                        {"name": "AA_extended"},
                    ],
                )

            attack_result, _, _ = analysis.show_solution()

            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/dec.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[
            {"name": "No corruption"},
            {"name": "AA"},
            {"name": "AA_extended"},
        ],
    )


@bp.route("/sec", methods=("GET", "POST"))
# @login_required
def sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/sec.html", fractional=[{"name": "Yes"}, {"name": "No"}]
            )
        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/sec.html", fractional=[{"name": "Yes"}, {"name": "No"}]
            )

        default_entry["key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/sec.html",
                    fractional=[{"name": "Yes"}, {"name": "No"}],
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/sec.html",
                    fractional=[{"name": "Yes"}, {"name": "No"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/sec.html",
                    fractional=[{"name": "Yes"}, {"name": "No"}],
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash("The JSON file is not valid.")
                return render_template(
                    "acabella_app/sec.html",
                    fractional=[{"name": "Yes"}, {"name": "No"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/sec.html",
                    fractional=[{"name": "Yes"}, {"name": "No"}],
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder

            # update is_fractional field in JSON
            # UPDATE: perhaps in the future and only for debugging
            # if analysis.is_scheme_fractional():
            #    default_entry["is_fractional"] = "true"
            # else:
            #    default_entry["is_fractional"] = "false"

            default_entry_json = json.dumps(default_entry, indent=2)

            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template(
        "acabella_app/sec.html", fractional=[{"name": "Yes"}, {"name": "No"}]
    )


@bp.route("/lxxh16_attack", methods=("GET", "POST"))
def lxxh16_attack():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        corruption_model = request.form.get("corruption_select")
        master_key = request.form["master_key"]
        unknown = request.form["unknown"]
        corr_vars = request.form["corr_vars"]

        mpk_ca_vars = request.form["mpk_ca_vars"]
        mpk_aa_vars = request.form["mpk_aa_vars"]
        mpk_vars = request.form["mpk_vars"]
        gp_vars = request.form["gp_vars"]

        default_entry = {
            "analysis": "master_key",
            "k": ["(alpha_i + r) / b", "r"],
            "master_key": "alpha_i",
            "unknown_vars": ["alpha_i", "r", "s"],
            "corruption_model": "mixed_CA_corr",
            "corruptable_vars": [{"type": "MPK_AA", "var": "b"}],
            "MPK_CA": [],
            "MPK_AA": ["alpha_i", "b"],
            "MPK_vars": [],
            "GP_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/lxxh16_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "Mixed CA"}],
            )

        default_entry["corruption_model"] = (
            "mixed_CA_corr"  # str(request.form.get('corruption_select'))
        )
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The description of the unknown variables is not correct.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash(
                    "The description of the variables obtained via corruption is not correct."
                )
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )
        else:
            default_entry["corruptable_vars"] = []

        if request.form["mpk_ca_vars"]:
            try:
                default_entry["MPK_CA"] = json.loads(request.form["mpk_ca_vars"])
            except:
                flash("The description of the CA MPK variables is not correct.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["mpk_aa_vars"]:
            try:
                default_entry["MPK_AA"] = json.loads(request.form["mpk_aa_vars"])
            except:
                flash("The description of the AA MPK variables is not correct.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["mpk_vars"]:
            try:
                default_entry["MPK_vars"] = json.loads(request.form["mpk_vars"])
            except:
                flash("The description of the MPK variables is not correct.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["GP_vars"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP variables is not correct.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

            master_params, corruptable_vars = parse_config.generate_master_key_params()
            if master_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(master_params, None, corruptable_vars, None, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/lxxh16_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

            attack_result, _, _ = analysis.show_solution()
            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/lxxh16_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "Mixed CA"}],
    )


@bp.route("/mgz19_attack", methods=("GET", "POST"))
def mgz19_attack():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        corruption_model = request.form.get("corruption_select")
        master_key = request.form["master_key"]
        unknown = request.form["unknown"]
        corr_vars = request.form["corr_vars"]

        mpk_ca_vars = request.form["mpk_ca_vars"]
        mpk_aa_vars = request.form["mpk_aa_vars"]
        mpk_vars = request.form["mpk_vars"]
        gp_vars = request.form["gp_vars"]

        default_entry = {
            "analysis": "master_key",
            "k": ["(alpha_i + r) / b", "r"],
            "master_key": "alpha_i",
            "unknown_vars": ["alpha_i", "r", "s"],
            "corruption_model": "AA",
            "corruptable_vars": [{"type": "MPK_AA", "var": "b"}],
            "MPK_CA": [],
            "MPK_AA": ["alpha_i", "b"],
            "MPK_vars": [],
            "GP_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/mgz19_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "Mixed CA"}],
            )

        default_entry["corruption_model"] = (
            "mixed_CA_corr"  # str(request.form.get('corruption_select'))
        )
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The description of the unknown variables is not correct.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash(
                    "The description of the variables obtained via corruption is not correct."
                )
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )
        else:
            default_entry["corruptable_vars"] = []

        if request.form["mpk_ca_vars"]:
            try:
                default_entry["MPK_CA"] = json.loads(request.form["mpk_ca_vars"])
            except:
                flash("The description of the CA MPK variables is not correct.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["mpk_aa_vars"]:
            try:
                default_entry["MPK_AA"] = json.loads(request.form["mpk_aa_vars"])
            except:
                flash("The description of the AA MPK variables is not correct.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["mpk_vars"]:
            try:
                default_entry["MPK_vars"] = json.loads(request.form["mpk_vars"])
            except:
                flash("The description of the MPK variables is not correct.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["GP_vars"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP variables is not correct.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

            master_params, corruptable_vars = parse_config.generate_master_key_params()
            if master_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(master_params, None, corruptable_vars, None, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/mgz19_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed CA"}],
                )

            attack_result, _, _ = analysis.show_solution()
            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/mgz19_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "Mixed CA"}],
    )


@bp.route("/yj12_attack", methods=("GET", "POST"))
def yj12_attack():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        corruption_model = request.form.get("corruption_select")
        master_key = request.form["master_key"]
        unknown = request.form["unknown"]
        corr_vars = request.form["corr_vars"]

        mpk_ca_vars = request.form["mpk_ca_vars"]
        mpk_aa_vars = request.form["mpk_aa_vars"]
        mpk_vars = request.form["mpk_vars"]
        gp_vars = request.form["gp_vars"]

        default_entry = {
            "analysis": "master_key",
            "k": ["(alpha_i + r) / b", "r"],
            "master_key": "alpha_i",
            "unknown_vars": ["alpha_i", "r", "s"],
            "corruption_model": "AA",
            "corruptable_vars": [{"type": "MPK_AA", "var": "b"}],
            "MPK_CA": [],
            "MPK_AA": ["alpha_i", "b"],
            "MPK_vars": [],
            "GP_vars": [],
        }

        # build JSON string

        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/yj12_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "Mixed AA"}],
            )

        default_entry["corruption_model"] = (
            "mixed_AA_corr"  # str(request.form.get('corruption_select'))
        )
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The description of the unknown variables is not correct.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash(
                    "The description of the variables obtained via corruption is not correct."
                )
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )
        else:
            default_entry["corruptable_vars"] = []

        if request.form["mpk_ca_vars"]:
            try:
                default_entry["MPK_CA"] = json.loads(request.form["mpk_ca_vars"])
            except:
                flash("The description of the CA MPK variables is not correct.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

        if request.form["mpk_aa_vars"]:
            try:
                default_entry["MPK_AA"] = json.loads(request.form["mpk_aa_vars"])
            except:
                flash("The description of the AA MPK variables is not correct.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

        if request.form["mpk_vars"]:
            try:
                default_entry["MPK_vars"] = json.loads(request.form["mpk_vars"])
            except:
                flash("The description of the MPK variables is not correct.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["GP_vars"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP variables is not correct.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

            master_params, corruptable_vars = parse_config.generate_master_key_params()
            if master_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(master_params, None, corruptable_vars, None, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/yj12_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "Mixed AA"}],
                )

            attack_result, _, _ = analysis.show_solution()
            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/yj12_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "Mixed AA"}],
    )


@bp.route("/po17_attack", methods=("GET", "POST"))
def po17_attack():

    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "decryption",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b", "s * b2"],
            "mpk": ["b"],
            "gp": [],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruption_model": "AA_extended",
            "corruptable_vars": [{"type": "MPK_AAi", "var": "b2"}],
            "MPK_AAi": ["b2"],
            "MPK_AAj": ["b"],
            "misc_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/po17_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "AA_extended"}],
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/po17_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "AA_extended"}],
            )

        default_entry["corruption_model"] = str(request.form.get("corruption_select"))
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash("The variables obtained via corruption are not correct.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["mpk_aai_vars"]:
            try:
                default_entry["MPK_AAi"] = json.loads(request.form["mpk_aai_vars"])
            except:
                flash("The contents of MPK_AAi are not correct.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["mpk_aaj_vars"]:
            try:
                default_entry["MPK_AAj"] = json.loads(request.form["mpk_aaj_vars"])
            except:
                flash("The contents of MPK_AAj are not correct.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["misc_vars"]:
            try:
                default_entry["misc_vars"] = json.loads(request.form["misc_vars"])
            except:
                flash("The description of the misc. vars is not correct.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["gp"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP vars is not correct.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

            dec_params, corruptable_vars = parse_config.generate_dec_key_params()
            if dec_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, dec_params, None, corruptable_vars, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/po17_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA_extended"}],
                )

            attack_result, _, _ = analysis.show_solution()

            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/po17_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "AA_extended"}],
    )


@bp.route("/yj14_attack", methods=("GET", "POST"))
def yj14_attack():

    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "decryption",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b", "s * b2"],
            "mpk": ["b"],
            "gp": [],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruption_model": "AA_extended",
            "corruptable_vars": [{"type": "MPK_AAi", "var": "b2"}],
            "MPK_AAi": ["b2"],
            "MPK_AAj": ["b"],
            "misc_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/yj14_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "AA"}],
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/yj14_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "AA"}],
            )

        default_entry["corruption_model"] = str(request.form.get("corruption_select"))
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash("The variables obtained via corruption are not correct.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

        if request.form["mpk_aai_vars"]:
            try:
                default_entry["MPK_AAi"] = json.loads(request.form["mpk_aai_vars"])
            except:
                flash("The contents of MPK_AAi are not correct.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

        if request.form["mpk_aaj_vars"]:
            try:
                default_entry["MPK_AAj"] = json.loads(request.form["mpk_aaj_vars"])
            except:
                flash("The contents of MPK_AAj are not correct.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

        if request.form["misc_vars"]:
            try:
                default_entry["misc_vars"] = json.loads(request.form["misc_vars"])
            except:
                flash("The description of the misc. vars is not correct.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["gp"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP vars is not correct.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

            dec_params, corruptable_vars = parse_config.generate_dec_key_params()
            if dec_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, dec_params, None, corruptable_vars, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/yj14_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "AA"}],
                )

            attack_result, _, _ = analysis.show_solution()

            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/yj14_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "AA"}],
    )


@bp.route("/yjr13_attack", methods=("GET", "POST"))
def yjr13_attack():

    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "decryption",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b", "s * b2"],
            "mpk": ["b"],
            "gp": [],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruption_model": "AA_extended",
            "corruptable_vars": [{"type": "MPK_AAi", "var": "b2"}],
            "MPK_AAi": ["b2"],
            "MPK_AAj": ["b"],
            "misc_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/yjr13_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "No corruption"}],
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/yjr13_attack.html",
                analysis_type=[
                    {"name": "Master key attack"},
                    {"name": "Decryption Attack"},
                    {"name": "Conditional Attack"},
                    {"name": "Complete"},
                    {"name": "Security"},
                ],
                corruption_type=[{"name": "No corruption"}],
            )

        default_entry["corruption_model"] = str(request.form.get("corruption_select"))
        default_entry["master_key"] = str(request.form["master_key"])

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

        if request.form["corr_vars"]:
            try:
                default_entry["corruptable_vars"] = json.loads(
                    request.form["corr_vars"]
                )
            except:
                flash("The variables obtained via corruption are not correct.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

        if request.form["mpk_aai_vars"]:
            try:
                default_entry["MPK_AAi"] = json.loads(request.form["mpk_aai_vars"])
            except:
                flash("The contents of MPK_AAi are not correct.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

        if request.form["mpk_aaj_vars"]:
            try:
                default_entry["MPK_AAj"] = json.loads(request.form["mpk_aaj_vars"])
            except:
                flash("The contents of MPK_AAj are not correct.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

        if request.form["misc_vars"]:
            try:
                default_entry["misc_vars"] = json.loads(request.form["misc_vars"])
            except:
                flash("The description of the misc. vars is not correct.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

        if request.form["gp_vars"]:
            try:
                default_entry["gp"] = json.loads(request.form["gp_vars"])
            except:
                flash("The description of the GP vars is not correct.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

            dec_params, corruptable_vars = parse_config.generate_dec_key_params()
            if dec_params is None:
                flash("The JSON input is not valid.")
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, dec_params, None, corruptable_vars, None)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/yjr13_attack.html",
                    analysis_type=[
                        {"name": "Master key attack"},
                        {"name": "Decryption Attack"},
                        {"name": "Conditional Attack"},
                        {"name": "Complete"},
                        {"name": "Security"},
                    ],
                    corruption_type=[{"name": "No corruption"}],
                )

            attack_result, _, _ = analysis.show_solution()

            attack_result.pop(0)  # remove mk placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                proof=None,
                attack="\n".join(attack_result),
            )  # posts)

    return render_template(
        "acabella_app/yjr13_attack.html",
        analysis_type=[
            {"name": "Master key attack"},
            {"name": "Decryption Attack"},
            {"name": "Conditional Attack"},
            {"name": "Complete"},
            {"name": "Security"},
        ],
        corruption_type=[{"name": "No corruption"}],
    )


@bp.route("/bbibe_sec", methods=("GET", "POST"))
def bbibe_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/bbibe_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template("acabella_app/bbibe_sec.html", fractional=[{"name": "No"}])


@bp.route("/rw13_sec", methods=("GET", "POST"))
def rw13_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/rw13_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template("acabella_app/rw13_sec.html", fractional=[{"name": "No"}])


@bp.route("/wat11_sec", methods=("GET", "POST"))
def wat11_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/wat11_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template("acabella_app/wat11_sec.html", fractional=[{"name": "No"}])


@bp.route("/wat11_II_sec", methods=("GET", "POST"))
def wat11_II_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template(
        "acabella_app/wat11_II_sec.html", fractional=[{"name": "No"}]
    )


@bp.route("/bsw07_sec", methods=("GET", "POST"))
def bsw07_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/bsw07_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template("acabella_app/bsw07_sec.html", fractional=[{"name": "No"}])


@bp.route("/abgw17_cpabe_sec", methods=("GET", "POST"))
def abgw17_cpabe_sec():
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        select = request.form.get("analysis_select")

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not body:
            error = "JSON description of the ABE scheme is required."

        # if not select:
        #    error = "Analysis type is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(body)
            except ValueError as e:
                flash("The JSON description of the ABE scheme is not valid.")
                return render_template(
                    "acabella_app/abgw17_cpabe_sec.html",
                    analysis_type=[{"name": "Complete"}],
                )

            msg = None

            match str(select):
                case "Master key attack":
                    master_params, corruptable_vars = (
                        parse_config.generate_master_key_params()
                    )

                    if master_params is None:
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/abgw17_cpabe_sec.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(master_params, None, corruptable_vars, None, None)
                    analysis.run()
                    attack_result, _, _ = analysis.show_solution()
                    attack_result.pop(0)  # remove mk placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                    )  # posts)

                case "Decryption Attack":
                    dec_params, corruptable_vars = (
                        parse_config.generate_dec_key_params()
                    )

                    if dec_params is None:
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/abgw17_cpabe_sec.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(None, dec_params, None, corruptable_vars, None)
                    analysis.run()
                    attack_result, _, _ = analysis.show_solution()
                    attack_result.pop(0)  # remove mk placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                    )  # posts)

                case "Security":
                    security_params = parse_config.generate_security_analysis_params()

                    if security_params is None:
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/abgw17_cpabe_sec.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(None, None, None, None, security_params)
                    analysis.run()
                    attack_result, proof_result, proof_header = analysis.show_solution()

                    attack_result.pop(0)  # remove sec placeholder
                    json_out = body

                    return render_template(
                        "acabella_app/index.html",
                        json_out=json_out,
                        attack="\n".join(attack_result),
                        proof=proof_result,
                        proof_header=proof_header,
                    )  # posts)

                case "Complete":
                    (
                        security_params,
                        master_params,
                        corruptable_vars_master,
                        dec_params,
                        corruptable_vars_dec,
                    ) = parse_config.generate_all_params()

                    if (
                        security_params is None
                        or master_params is None
                        or dec_params is None
                    ):
                        flash("The JSON description of the ABE scheme is not valid.")
                        return render_template(
                            "acabella_app/abgw17_cpabe_sec.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    analysis = AnalysisWithCorruption()
                    analysis.init(
                        master_params,
                        dec_params,
                        corruptable_vars_master,
                        corruptable_vars_dec,
                        security_params,
                    )

                    try:
                        analysis.run()
                    except:
                        flash(
                            "The analysis process found an error: The JSON input is not correct."
                        )
                        return render_template(
                            "acabella_app/abgw17_cpabe_sec.html",
                            analysis_type=[{"name": "Complete"}],
                        )

                    proof_result = None

                    attack_result, proof_result, proof_header = analysis.show_solution()

                    json_out = body

                    master_key_result = []
                    decryption_attack_result = []
                    sec_result = []

                    mk_start = False
                    da_start = False

                    # collect sec analysis

                    attack_result.pop(0)

                    for line in attack_result:
                        sec_result.append(line)
                        if line == "mk_placeholder":
                            sec_result.pop()
                            break

                    # collect mk analysis

                    for line in attack_result:
                        if mk_start:
                            master_key_result.append(line)
                        if line == "mk_placeholder":
                            mk_start = True
                        if line == "da_placeholder":
                            master_key_result.pop()
                            break

                    # collect da analysis

                    for line in attack_result:
                        if da_start:
                            decryption_attack_result.append(line)
                        if line == "da_placeholder":
                            da_start = True

                    return render_template(
                        "acabella_app/index.html",
                        master_key_result="\n".join(master_key_result),
                        decryption_attack_result="\n".join(decryption_attack_result),
                        is_complete="true",
                        json_out=json_out,
                        attack="\n".join(sec_result),
                        proof=proof_result,
                        proof_header=proof_header,
                    )  # posts)

                case _:
                    msg = "Incorrect analysis type"

    return render_template(
        "acabella_app/abgw17_cpabe_sec.html", analysis_type=[{"name": "Complete"}]
    )


@bp.route("/abgw17_ibe1_sec", methods=("GET", "POST"))
def abgw17_ibe1_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template(
        "acabella_app/abgw17_ibe1_sec.html", fractional=[{"name": "No"}]
    )


@bp.route("/abgw17_kpabe_sec", methods=("GET", "POST"))
def abgw17_kpabe_sec():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template(
        "acabella_app/abgw17_kpabe_sec.html", fractional=[{"name": "No"}]
    )


@bp.route("/newcpabe_ii", methods=("GET", "POST"))
def newcpabe_ii():
    if request.method == "POST":
        title = request.form["title"]
        k = request.form["k"]
        c = request.form["c"]
        master_key = request.form["master_key"]

        default_entry = {
            "analysis": "security",
            "k": ["(alpha_i + r) / b", "r"],
            "c": ["s * b"],
            "mpk": ["b"],
            "key": "alpha_i * s",
            "unknown_vars": ["alpha_i", "r", "s", "b"],
            "corruptable_vars": [],
        }

        # build JSON string
        try:
            default_entry["k"] = json.loads(request.form["k"])
        except:
            flash("The key encodings description is not correct.")
            return render_template(
                "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["c"] = json.loads(request.form["c"])
        except:
            flash("The ciphertext encodings description is not correct.")
            return render_template(
                "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
            )

        try:
            default_entry["key"] = str(request.form["master_key"])
        except:
            flash("The key description is not correct.")
            return render_template(
                "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
            )

        # optional fields

        if request.form["unknown"]:
            try:
                default_entry["unknown_vars"] = json.loads(request.form["unknown"])
            except:
                flash("The unknown variables description is not correct.")
                return render_template(
                    "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
                )

        if request.form["mpk"]:
            try:
                default_entry["mpk"] = json.loads(request.form["mpk"])
            except:
                flash("The MPK description is not correct.")
                return render_template(
                    "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
                )

        default_entry_json = json.dumps(default_entry, indent=2)

        error = None

        if not title:
            error = "ABE scheme identifier is required."

        if not k:
            error = "List of key encodings is required."

        if not c:
            error = "List of ciphertext encodings is required."

        if not master_key:
            error = "Master key representation is required."

        if error is not None:
            flash(error)

        else:

            # is JSON valid ?

            parse_config = ParseConfig()

            try:
                parse_config.init_with_str(default_entry_json)
            except ValueError as e:
                flash("JSON input file is not valid.")
                return render_template(
                    "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
                )

            security_params = parse_config.generate_security_analysis_params()

            if security_params is None:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
                )

            analysis = AnalysisWithCorruption()
            analysis.init(None, None, None, None, security_params)

            try:
                analysis.run()
            except:
                flash(
                    "The analysis process found an error: The JSON input is not correct."
                )
                return render_template(
                    "acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}]
                )

            attack_result, proof_result, proof_header = analysis.show_solution()

            attack_result.pop(0)  # remove sec placeholder
            json_out = default_entry_json

            return render_template(
                "acabella_app/index.html",
                json_out=json_out,
                attack="\n".join(attack_result),
                proof=proof_result,
                proof_header=proof_header,
            )  # posts)

    return render_template("acabella_app/newcpabe_ii.html", fractional=[{"name": "No"}])

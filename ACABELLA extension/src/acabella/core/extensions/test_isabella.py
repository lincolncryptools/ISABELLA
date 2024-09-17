import pytest
from sympy import symbols, Matrix, parse_expr, zeros, sympify
from acabella.core.extensions.isabella import (
    first_pass,
    second_pass,
    third_pass_parse_ciphertext_polynomials,
    fourth_pass_validate_encodings,
    setup_penc_vector,
    decompose_penc,
    find_kernel_vector,
    decompose_ciphertext_polynomials,
    decompose_ciphertext_primed_polynomials,
    construct_substitution_vectors,
    # verify_substitution_vectors,
    analyze,
)
import re


def process_test_inputs(example):
    def extract_symbols(expressions):
        pattern = r"\b[a-zA-Z_][a-zA-Z0-9_]*\b"
        return set(re.findall(pattern, " ".join(expressions)))

    # Extract all symbols
    all_expressions = example["kenc"] + example["cenc"]
    all_symbols = (
        extract_symbols(all_expressions)
        | set(example["abenc"])
        | set(example["known_vars"])
    )

    # Identify known and unknown variables
    known_vars = set(example["known_vars"])
    unknown_vars = all_symbols - known_vars

    # Create a dictionary of symbols
    symbols_dict = {sym: symbols(sym) for sym in all_symbols}
    unknown_vars_syms = [symbols_dict[var] for var in unknown_vars]

    # Helper method to convert expression strings to sympy polynomials
    def to_polynomials(expressions):
        return [
            sympify(expr, locals=symbols_dict).as_poly(*unknown_vars_syms)
            for expr in expressions
        ]

    def to_expressions(expressions):
        return [sympify(expr, locals=symbols_dict).as_expr() for expr in expressions]

    def to_expression(item):
        if isinstance(item, str):
            return sympify(item, locals=symbols_dict)
        else:
            return item

    # Helper method to convert list of lists to Matrix, unless marked to skip
    def to_matrix(data):
        if isinstance(data, list):
            # Check if the first element is a list (indicating a 2D list)
            if data and isinstance(data[0], list):
                return Matrix([[to_expression(item) for item in row] for row in data])
            else:
                # Handle 1D list: convert to a column matrix
                return Matrix([to_expression(item) for item in data]).T
        elif isinstance(data, dict):
            result_dict = {}
            for key, value in data.items():
                if key in ["stilde", "v2"]:
                    result_dict[key] = value  # Directly pass non-matrix values
                else:
                    # Apply matrix conversion depending on whether value is 1D or 2D list
                    result_dict[key] = to_matrix(
                        value
                    )  # Recursively call to_matrix to handle 1D or 2D lists
            return result_dict
        else:
            raise TypeError(
                f"Unsupported data type for matrix conversion: {type(data)}"
            )

    if (
        "v_c_prime" in example["expected_outputs"]
        and "M_c_prime" in example["expected_outputs"]
    ):
        example["expected_outputs"]["v_c_prime"] = Matrix(
            to_expressions(example["expected_outputs"]["v_c_prime"])
        )
        example["expected_outputs"]["M_c_prime"] = Matrix(
            to_matrix(example["expected_outputs"]["M_c_prime"])
        )
    else:
        example["expected_outputs"]["v_c_prime"] = None
        example["expected_outputs"]["M_c_prime"] = None

    example.update(
        {
            "kenc": to_polynomials(example["kenc"]),
            "cenc": to_polynomials(example["cenc"]),
            "abenc": {symbols(var) for var in example["abenc"]},
            "known_vars": {symbols(var) for var in known_vars},
            "corruptable_vars": {symbols(var) for var in example["corruptable_vars"]},
            "expected_outputs": {
                "first_pass": {
                    "key_polynomials": to_polynomials(
                        example["expected_outputs"]["first_pass"]["key_polynomials"]
                    ),
                    "ciphertext_polynomials": to_polynomials(
                        example["expected_outputs"]["first_pass"][
                            "ciphertext_polynomials"
                        ]
                    ),
                    "key_non_lone_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["first_pass"][
                            "key_non_lone_vars"
                        ]
                    ],
                    "key_lone_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["first_pass"][
                            "key_lone_vars"
                        ]
                    ],
                    "ciphertext_non_lone_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["first_pass"][
                            "ciphertext_non_lone_vars"
                        ]
                    ],
                },
                "second_pass": {
                    "master_key_semi_common_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["second_pass"][
                            "master_key_semi_common_vars"
                        ]
                    ],
                    "common_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["second_pass"][
                            "common_vars"
                        ]
                    ],
                    "unused_abenc_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["second_pass"][
                            "unused_abenc_vars"
                        ]
                    ],
                },
                "third_pass": {
                    "ciphertext_primed_polynomials": to_polynomials(
                        example["expected_outputs"]["third_pass"][
                            "ciphertext_primed_polynomials"
                        ]
                    ),
                    "ciphertext_non_primed_polynomials": to_polynomials(
                        example["expected_outputs"]["third_pass"][
                            "ciphertext_non_primed_polynomials"
                        ]
                    ),
                    "ciphertext_primed_lone_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["third_pass"][
                            "ciphertext_primed_lone_vars"
                        ]
                    ],
                    "ciphertext_lone_vars": [
                        symbols(var)
                        for var in example["expected_outputs"]["third_pass"][
                            "ciphertext_lone_vars"
                        ]
                    ],
                },
                "fourth_pass": {
                    "result": example["expected_outputs"]["fourth_pass"]["result"]
                },
                "blinding_value": sympify(
                    example["expected_outputs"]["blinding_value"], locals=symbols_dict
                ).as_poly(*unknown_vars_syms),
                "penc": to_polynomials(example["expected_outputs"]["penc"]),
                "v1": Matrix(to_expressions(example["expected_outputs"]["v1"])),
                "v2": Matrix(to_expressions(example["expected_outputs"]["v2"])),
                "M": Matrix(to_matrix(example["expected_outputs"]["M"])),
                "tv": Matrix(example["expected_outputs"]["tv"]),
                "w": Matrix(to_expressions(example["expected_outputs"]["w"])),
                "w_cor": Matrix(to_expressions(example["expected_outputs"]["w_cor"])),
                "v_c": Matrix(to_expressions(example["expected_outputs"]["v_c"])),
                "M_c": Matrix(to_matrix(example["expected_outputs"]["M_c"])),
                "v_c_prime": example["expected_outputs"]["v_c_prime"],
                "M_c_prime": example["expected_outputs"]["M_c_prime"],
                "substitution_vector": to_matrix(
                        example["expected_outputs"]["substitution_vector"]
                )
            },
        }
    )

    if (
        "failures" in example
        and "second_pass" in example["failures"]
        and "key_polynomials_non_disjoint" in example["failures"]["second_pass"]
    ):
        example["failures"]["second_pass"]["key_polynomials_non_disjoint"] = (
            to_polynomials(
                example["failures"]["second_pass"]["key_polynomials_non_disjoint"]
            )
        )

    return example


@pytest.fixture
def example_inputs():
    inputs = {
        "simple": {
            "abenc": ["alpha1", "alpha2", "b10", "b11", "b20", "b21"],
            "kenc": [
                "alpha1 + rgid * (b10 + y1 * b11)",
                "alpha2 + rgid * (b20 + y2 * b21)",
                "rgid",
            ],
            "cenc": [
                "A12*v2p + s1 * (b10 + x1 * b11)",
                "A11*stilde + A12*v2 + s1 * alpha1",
                "s1",
                "A22*v2p + s2 * (b20 + x2 * b21)",
                "A21*stilde + A22*v2 + s2 * alpha2",
                "s2",
            ],
            "known_vars": ["x1", "x2", "y1", "y2", "A11", "A12", "A21", "A22"],
            "corruptable_vars": ["alpha1", "b10", "b11"],
            "expected_outputs": {
                "first_pass": {
                    "key_polynomials": [
                        "alpha1 + rgid * (b10 + y1 * b11)",
                        "alpha2 + rgid * (b20 + y2 * b21)",
                    ],
                    "key_non_lone_vars": ["rgid"],
                    "key_lone_vars": [],
                    "ciphertext_polynomials": [
                        "A12*v2p + s1 * (b10 + x1 * b11)",
                        "A11*stilde + A12*v2 + s1 * alpha1",
                        "A22*v2p + s2 * (b20 + x2 * b21)",
                        "A21*stilde + A22*v2 + s2 * alpha2",
                    ],
                    "ciphertext_non_lone_vars": ["s1", "s2"],
                },
                "second_pass": {
                    "master_key_semi_common_vars": ["alpha1", "alpha2"],
                    "common_vars": ["b10", "b11", "b20", "b21"],
                    "unused_abenc_vars": [],
                },
                "third_pass": {
                    "ciphertext_primed_polynomials": [
                        "A11*stilde + A12*v2 + s1 * alpha1",
                        "A21*stilde + A22*v2 + s2 * alpha2",
                    ],
                    "ciphertext_non_primed_polynomials": [
                        "A12*v2p + s1*b10 + s1*x1*b11",
                        "A22*v2p + s2*b20 + s2*x2*b21",
                    ],
                    "ciphertext_primed_lone_vars": ["stilde", "v2"],
                    "ciphertext_lone_vars": ["v2p"],
                },
                "fourth_pass": {
                    "result": True,
                },
                "blinding_value": "stilde",
                "penc": [
                    "alpha1 * s1 + b10 * rgid * s1 + b11 * rgid * s1 * y1",
                    "alpha2 * s1 + b20 * rgid * s1 + b21 * rgid * s1 * y2",
                    "alpha1 * s2 + b10 * rgid * s2 + b11 * rgid * s2 * y1",
                    "alpha2 * s2 + b20 * rgid * s2 + b21 * rgid * s2 * y2",
                    "A12 * rgid * v2p + b10 * rgid * s1 + b11 * rgid * s1 * x1",
                    "A22 * rgid * v2p + b20 * rgid * s2 + b21 * rgid * s2 * x2",
                    "A11 * stilde + A12 * v2 + alpha1 * s1",
                    "A21 * stilde + A22 * v2 + alpha2 * s2",
                ],
                "v1": [
                    "alpha1 * s1",
                    "alpha1 * s2",
                    "alpha2 * s1",
                    "alpha2 * s2",
                    "stilde",
                    "v2",
                ],
                "v2": [
                    "rgid * s1 * b10",
                    "rgid * s1 * b11",
                    "rgid * s1 * b20",
                    "rgid * s1 * b21",
                    "rgid * s2 * b10",
                    "rgid * s2 * b11",
                    "rgid * s2 * b20",
                    "rgid * s2 * b21",
                    "rgid * v2p",
                ],
                "M": [
                    [1, 0, 0, 0, 0, 0, 1, "y1", 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 1, 0, 0, 0, 0, 0, 1, "y2", 0, 0, 0, 0, 0],
                    [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, "y1", 0, 0, 0],
                    [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, "y2", 0],
                    [0, 0, 0, 0, 0, 0, 1, "x1", 0, 0, 0, 0, 0, 0, "A12"],
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", "A22"],
                    [1, 0, 0, 0, "A11", "A12", 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 1, "A21", "A22", 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ],
                "tv": [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "v_c_prime": [
                    "alpha1*s1",
                    "alpha2*s1",
                    "alpha1*s2",
                    "alpha2*s2",
                    "stilde",
                    "v2",
                ],
                "M_c_prime": [[1, 0, 0, 0, "A11", "A12"], [0, 0, 0, 1, "A21", "A22"]],
                "w": [
                    "-A11",
                    0,
                    0,
                    "-A21",
                    1,
                    0,
                    "A11*x1/(x1 - y1)",
                    "-A11/(x1 - y1)",
                    0,
                    0,
                    0,
                    0,
                    "A21*x2/(x2 - y2)",
                    "-A21/(x2 - y2)",
                    0,
                ],
                "w_cor": [0, 0, 0, "A11*A22/A12 - A21", 1, "-A11/A12", 0, 0, 0, 0, 0, 0, "x2*(-A11*A22 + A12*A21)/(A12*(x2 - y2))", "(A11*A22 - A12*A21)/(A12*(x2 - y2))", 0],
                "v_c": [
                    "b10*s1",
                    "b11*s1",
                    "b20*s1",
                    "b21*s1",
                    "b10*s2",
                    "b11*s2",
                    "b20*s2",
                    "b21*s2",
                    "v2p",
                ],
                "M_c": [
                    [1, "x1", 0, 0, 0, 0, 0, 0, "A12"],
                    [0, 0, 0, 0, 0, 0, 1, "x2", "A22"],
                ],
                "substitution_vector": {
                    "s1": [[1], [0]],
                    "s2": [[0], [1]],
                    "b10": [[0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0]],
                    "b11": [[0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0]],
                    "b20": [[0, 1, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 1, "A22/A12"]],
                    "b21": [[0, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 0, "-1/x2", 0]],
                    "v2p": [0, 0, 0, 0, 0, 0, "-1/A12"],
                    "alpha1": [["-A11"], [0]],
                    "alpha2": [[0], ["-A21"]],
                    "stilde": 1,
                    "v2": 0,
                    "rgid": [
                        ["A11*x1/(x1 - y1)"],
                        [0],
                        [0],
                        [0],
                        [0],
                        ["A21*x2/(x2 - y2)"],
                        [0],
                    ],
                },
            },
            "failures": {
                "second_pass": {
                    "key_polynomials_non_disjoint": [
                        "alpha1 + rgid * (alpha2 + y1 * b11)",
                        "alpha2 + rgid * (b20 + y2 * b21)",
                    ]
                },
                "third_pass": {
                    "invalid_ciphertext_polynomials": [
                        "A12*v2p + s1 * (b10 + x1 * b11)",
                        "A11*stilde + A12*v2 + s1 * alpha1",
                        "s1",
                        "A22*v2p + s2 * (b20 + x2 * b21)",
                        "A21*stilde + A22*v2 + s2 * alpha2",
                        "s2",
                        "A31*v3p + s3 * (b30 + x3 * alpha3)",
                    ]
                },
                "fourth_pass": {},
            },
        },
        "ven23_s5": {
            "abenc": ["alpha1", "alpha2", "b110", "b111", "b220", "b221"],
            "kenc": [
                "alpha1 + rgid * b1 + r1 * bp1",
                "r1 * (b110 + x1 * b111)",
                "alpha2 + rgid * b2 + r2 * bp2",
                "r2 * (b220 + x2 * b221)",
                "rgid",
                "r1",
                "r2",
            ],
            "cenc": [
                "A12*v2p + s1 * b1",
                "A11*stilde + A12*v2 + s1 * alpha1",
                "s1 * bp1 + sp1 * (b110 + x1 * b111)",
                "s1",
                "sp1",
                "A22*v2p + s2 * b2",
                "A21*stilde + A22*v2 + s2 * alpha2",
                "s1 * bp2 + sp1 * b221",
                "sp1 * (b220 + x2 * b221)",
                "s2",
            ],
            "known_vars": ["A12", "A11", "A21", "A22", "x1", "x2"],
            "corruptable_vars": ["alpha2", "b220", "b222"],
            "expected_outputs": {
                "first_pass": {
                    "key_polynomials": [
                        "alpha1 + rgid * b1 + r1 * bp1",
                        "r1 * (b110 + x1 * b111)",
                        "alpha2 + rgid * b2 + r2 * bp2",
                        "r2 * (b220 + x2 * b221)",
                    ],
                    "key_non_lone_vars": ["rgid", "r1", "r2"],
                    "key_lone_vars": [],
                    "ciphertext_polynomials": [
                        "A12*v2p + s1 * b1",
                        "A11*stilde + A12*v2 + s1 * alpha1",
                        "s1 * bp1 + sp1 * (b110 + x1 * b111)",
                        "A22*v2p + s2 * b2",
                        "A21*stilde + A22*v2 + s2 * alpha2",
                        "s1 * bp2 + sp1 * b221",
                        "sp1 * (b220 + x2 * b221)",
                    ],
                    "ciphertext_non_lone_vars": ["s1", "sp1", "s2"],
                },
                "second_pass": {
                    "master_key_semi_common_vars": ["alpha1", "alpha2"],
                    "common_vars": [
                        "b110",
                        "b111",
                        "b220",
                        "b221",
                        "b1",
                        "b2",
                        "bp1",
                        "bp2",
                    ],
                    "unused_abenc_vars": [],
                },
                "third_pass": {
                    "ciphertext_primed_polynomials": [
                        "A11*stilde + A12*v2 + s1 * alpha1",
                        "A21*stilde + A22*v2 + s2 * alpha2",
                    ],
                    "ciphertext_non_primed_polynomials": [
                        "A12*v2p + s1 * b1",
                        "s1 * bp1 + sp1 * b110 + sp1 * x1 * b111",
                        "A22*v2p + s2 * b2",
                        "s1 * bp2 + sp1 * b221",
                        "sp1 * b220 + sp1 * x2 * b221",
                    ],
                    "ciphertext_primed_lone_vars": ["stilde", "v2"],
                    "ciphertext_lone_vars": ["v2p"],
                },
                "fourth_pass": {
                    "result": True,
                },
                "blinding_value": "stilde",
                "penc": [
                    "r1*s1*bp1 + b1*s1*rgid + alpha1*s1",
                    "x1*r1*b111*s1 + r1*b110*s1",
                    "r2*bp2*s1 + alpha2*s1 + b2*s1*rgid",
                    "x2*r2*b221*s1 + r2*s1*b220",
                    "r1*sp1*bp1 + b1*sp1*rgid + alpha1*sp1",
                    "x1*r1*b111*sp1 + r1*b110*sp1",
                    "r2*bp2*sp1 + alpha2*sp1 + b2*sp1*rgid",
                    "x2*r2*b221*sp1 + r2*sp1*b220",
                    "r1*bp1*s2 + b1*s2*rgid + alpha1*s2",
                    "x1*r1*b111*s2 + r1*b110*s2",
                    "r2*bp2*s2 + alpha2*s2 + b2*s2*rgid",
                    "x2*r2*b221*s2 + r2*b220*s2",
                    "A12*v2p*rgid + b1*s1*rgid",
                    "x1*b111*sp1*rgid + b110*sp1*rgid + s1*bp1*rgid",
                    "A22*v2p*rgid + b2*s2*rgid",
                    "b221*sp1*rgid + bp2*s1*rgid",
                    "x2*b221*sp1*rgid + sp1*b220*rgid",
                    "A12*v2p*r1 + r1*b1*s1",
                    "x1*r1*b111*sp1 + r1*b110*sp1 + r1*s1*bp1",
                    "A22*v2p*r1 + r1*b2*s2",
                    "r1*b221*sp1 + r1*bp2*s1",
                    "x2*r1*b221*sp1 + r1*sp1*b220",
                    "A12*v2p*r2 + r2*b1*s1",
                    "x1*r2*b111*sp1 + r2*b110*sp1 + r2*s1*bp1",
                    "A22*v2p*r2 + r2*b2*s2",
                    "r2*b221*sp1 + r2*bp2*s1",
                    "x2*r2*b221*sp1 + r2*sp1*b220",
                    "A11 * stilde + A12 * v2 + alpha1 * s1",
                    "A21 * stilde + A22 * v2 + alpha2 * s2",
                ],
                "v1": [
                    "alpha1 * s1",
                    "alpha1 * sp1",
                    "alpha1 * s2",
                    "alpha2 * s1",
                    "alpha2 * sp1",
                    "alpha2 * s2",
                    "stilde",
                    "v2",
                ],
                "v2": [
                    "b110 * rgid * s1",
                    "b111 * rgid * s1",
                    "b220 * rgid * s1",
                    "b221 * rgid * s1",
                    "b1 * rgid * s1",
                    "b2 * rgid * s1",
                    "bp1 * rgid * s1",
                    "bp2 * rgid * s1",
                    "b110 * rgid * sp1",
                    "b111 * rgid * sp1",
                    "b220 * rgid * sp1",
                    "b221 * rgid * sp1",
                    "b1 * rgid * sp1",
                    "b2 * rgid * sp1",
                    "bp1 * rgid * sp1",
                    "bp2 * rgid * sp1",
                    "b110 * rgid * s2",
                    "b111 * rgid * s2",
                    "b220 * rgid * s2",
                    "b221 * rgid * s2",
                    "b1 * rgid * s2",
                    "b2 * rgid * s2",
                    "bp1 * rgid * s2",
                    "bp2 * rgid * s2",
                    "b110 * r1 * s1",
                    "b111 * r1 * s1",
                    "b220 * r1 * s1",
                    "b221 * r1 * s1",
                    "b1 * r1 * s1",
                    "b2 * r1 * s1",
                    "bp1 * r1 * s1",
                    "bp2 * r1 * s1",
                    "b110 * r1 * sp1",
                    "b111 * r1 * sp1",
                    "b220 * r1 * sp1",
                    "b221 * r1 * sp1",
                    "b1 * r1 * sp1",
                    "b2 * r1 * sp1",
                    "bp1 * r1 * sp1",
                    "bp2 * r1 * sp1",
                    "b110 * r1 * s2",
                    "b111 * r1 * s2",
                    "b220 * r1 * s2",
                    "b221 * r1 * s2",
                    "b1 * r1 * s2",
                    "b2 * r1 * s2",
                    "bp1 * r1 * s2",
                    "bp2 * r1 * s2",
                    "b110 * r2 * s1",
                    "b111 * r2 * s1",
                    "b220 * r2 * s1",
                    "b221 * r2 * s1",
                    "b1 * r2 * s1",
                    "b2 * r2 * s1",
                    "bp1 * r2 * s1",
                    "bp2 * r2 * s1",
                    "b110 * r2 * sp1",
                    "b111 * r2 * sp1",
                    "b220 * r2 * sp1",
                    "b221 * r2 * sp1",
                    "b1 * r2 * sp1",
                    "b2 * r2 * sp1",
                    "bp1 * r2 * sp1",
                    "bp2 * r2 * sp1",
                    "b110 * r2 * s2",
                    "b111 * r2 * s2",
                    "b220 * r2 * s2",
                    "b221 * r2 * s2",
                    "b1 * r2 * s2",
                    "b2 * r2 * s2",
                    "bp1 * r2 * s2",
                    "bp2 * r2 * s2",
                    "rgid * v2p",
                    "r1 * v2p",
                    "r2 * v2p"
                ],
                "M": [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A12", 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, "x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A22", 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A12", 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, "x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A22", 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A12"], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, "x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, "A22"], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "x2", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, "A11", "A12", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 1, "A21", "A22", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
                "tv": [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "w": ["-A11", 0, 0, 0, 0, "-A21", 1, 0, 0, 0, 0, 0, "A11", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A11*A22/A12", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "-A11*A22/A12 + A21", "-A11/A12", 0, 0],
                "w_cor": ["-A11 + A12*A21/A22", 0, 0, 0, 0, 0, 1, "-A21/A22", 0, 0, 0, 0, "A11 - A12*A21/A22", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A11*A22/A12 - A21", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "-A11*A22/A12 + A21", "-A11/A12 + A21/A22", 0, 0],
                "v_c": [
                    "b110*s1",
                    "b111*s1",
                    "b220*s1",
                    "b221*s1",
                    "b1*s1",
                    "b2*s1",
                    "bp1*s1",
                    "bp2*s1",
                    "b110*sp1",
                    "b111*sp1",
                    "b220*sp1",
                    "b221*sp1",
                    "b1*sp1",
                    "b2*sp1",
                    "bp1*sp1",
                    "bp2*sp1",
                    "b110*s2",
                    "b111*s2",
                    "b220*s2",
                    "b221*s2",
                    "b1*s2",
                    "b2*s2",
                    "bp1*s2",
                    "bp2*s2",
                    "v2p",
                ],
                "M_c": [
                    [
                        0,
                        0,
                        0,
                        0,
                        1,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        "A12",
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        1,
                        0,
                        1,
                        "x1",
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        1,
                        0,
                        0,
                        "A22",
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        1,
                        0,
                        0,
                        0,
                        1,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        1,
                        "x2",
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                ],
                "v_c_prime": [
                    "alpha1*s1",
                    "alpha2*s1",
                    "alpha1*sp1",
                    "alpha2*sp1",
                    "alpha1*s2",
                    "alpha2*s2",
                    "stilde",
                    "v2",
                ],
                "M_c_prime": [
                    [1, 0, 0, 0, 0, 0, "A11", "A12"],
                    [0, 0, 0, 0, 0, 1, "A21", "A22"],
                ],
                "substitution_vector": {
                    "s1": [[1], [0], [0]],
                    "sp1": [[0], [1], [0]],
                    "s2": [[0], [0], [1]],
                    "b110": [
                        [1, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
                    ],
                    "b111": [
                        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, "-1/x1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0,     0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
                    ],
                    "b220": [
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    ],
                    "b221": [
                        [0, 0, 0, 1, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
                    ],
                    "b1": [
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
                    ],
                    "b2": [
                        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,       0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,       0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A22/A12"]
                    ],
                    "bp1": [
                        [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
                    ],
                    "bp2": [
                        [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
                    ],
                    "v2p": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "-1/A12"],
                    "alpha1": [["-A11"], [0], [0]],
                    "alpha2": [[0], [0], ["-A21"]],
                    "stilde": 1,
                    "v2": 0,
                    "rgid": [
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        ["A11"],
                    ],
                    "r1": [
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0],
                        [0]
                    ],
                    "r2": [
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        [                 0],
                        ["-A11*A22/A12 + A21"],
                        [                 0]]
                },
            },
        },
        "rvv_decentralized": {
            "abenc": ["alpha1", "alpha2", "b1", "b2", "b3"],
            "kenc": [
                "(alpha1 + vgid)*A111 + v12*A112 + r11 * b1",
                "(alpha1 + vgid)*A121 + v12*A122 + r12 * b2",
                "(alpha2 - vgid)*A211 + v22*A212 + r21 * b1",
                "(alpha2 - vgid)*A221 + v22*A222 + r23 * b3",
                "r11",
                "r12",
                "r21",
                "r23",
            ],
            "cenc": ["s*b1", "s*b2", "s"],
            "known_vars": [
                "A111",
                "A112",
                "A121",
                "A122",
                "A211",
                "A212",
                "A221",
                "A222",
            ],
            "corruptable_vars": ["alpha2"],
            "expected_outputs": {
                "first_pass": {
                    "key_polynomials": [
                        "(alpha1 + vgid)*A111 + v12*A112 + r11 * b1",
                        "(alpha1 + vgid)*A121 + v12*A122 + r12 * b2",
                        "(alpha2 - vgid)*A211 + v22*A212 + r21 * b1",
                        "(alpha2 - vgid)*A221 + v22*A222 + r23 * b3",
                    ],
                    "key_non_lone_vars": ["r11", "r12", "r21", "r23"],
                    "key_lone_vars": ["vgid", "v12", "v22"],
                    "ciphertext_polynomials": ["s*b1", "s*b2"],
                    "ciphertext_non_lone_vars": ["s"],
                },
                "second_pass": {
                    "master_key_semi_common_vars": ["alpha1", "alpha2"],
                    "common_vars": ["b1", "b2", "b3"],
                    "unused_abenc_vars": [],
                },
                "third_pass": {
                    "ciphertext_primed_polynomials": [],
                    "ciphertext_non_primed_polynomials": ["s*b1", "s*b2"],
                    "ciphertext_primed_lone_vars": [],
                    "ciphertext_lone_vars": [],
                },
                "fourth_pass": {
                    "result": True,
                },
                "blinding_value": "(alpha1 + alpha2)*s",
                "penc": [
                    "A111*alpha1*s + b1*r11*s + A111*vgid*s + A112*v12*s",
                    "A121*alpha1*s + A121*vgid*s + r12*b2*s + A122*v12*s",
                    "A211*alpha2*s + b1*r21*s - A211*vgid*s + A212*v22*s",
                    "A221*alpha2*s - A221*vgid*s + A222*v22*s + b3*r23*s",
                    "b1*r11*s",
                    "b2*r11*s",
                    "b1*r12*s",
                    "r12*b2*s",
                    "b1*r21*s",
                    "b2*r21*s",
                    "b1*r23*s",
                    "r23*b2*s",
                ],
                "v1": [
                    "alpha1 * s",
                    "alpha2 * s",
                ],
                "v2": [
                    "b1 * r11 * s",
                    "b2 * r11 * s",
                    "b3 * r11 * s",
                    "b1 * r12 * s",
                    "b2 * r12 * s",
                    "b3 * r12 * s",
                    "b1 * r21 * s",
                    "b2 * r21 * s",
                    "b3 * r21 * s",
                    "b1 * r23 * s",
                    "b2 * r23 * s",
                    "b3 * r23 * s",
                    "s * vgid",
                    "s * v12",
                    "s * v22",
                ],
                "M": [
                    ["A111", 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A111", "A112", 0],
                    ["A121", 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, "A121", "A122", 0],
                    [0, "A211", 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, "-A211", 0, "A212"],
                    [0, "A221", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, "-A221", 0, "A222"],
                    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
                ],
                "tv": [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "w": [
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    "A211*A222/A212 - A221",
                    -1,
                    0,
                    "-A211/A212",
                ],
                "w_cor": [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "A211*A222/A212 - A221", -1, 0, "-A211/A212"],
                "v_c": ["b1*s", "b2*s", "b3*s"],
                "M_c": [[1, 0, 0], [0, 1, 0]],
                "substitution_vector": {
                    "s": [[1]],
                    "b1": [[0]],
                    "b2": [[0]],
                    "b3": [[1]],
                    "alpha1": [[1]],
                    "alpha2": [[0]],
                    "vgid": [[-1]],
                    "v12": [[0]],
                    "v22": [["-A211/A212"]],
                    "r11": [[0]],
                    "r12": [[0]],
                    "r21": [[0]],
                    "r23": [["A211*A222/A212 - A221"]],
                },
            },
        },
    }

    for key, example in inputs.items():
        inputs[key] = process_test_inputs(example)

    return inputs


def test_first_pass(example_inputs):
    for example in example_inputs.values():
        (
            key_polynomials,
            key_non_lone_vars,
            key_lone_vars,
            ciphertext_polynomials,
            ciphertext_non_lone_vars,
        ) = first_pass(example["kenc"], example["cenc"], example["abenc"])
        expected_output = example["expected_outputs"]["first_pass"]
        assert key_polynomials == expected_output["key_polynomials"]
        assert key_non_lone_vars == expected_output["key_non_lone_vars"]
        assert set(key_lone_vars) == set(expected_output["key_lone_vars"])
        assert ciphertext_polynomials == expected_output["ciphertext_polynomials"]
        assert ciphertext_non_lone_vars == expected_output["ciphertext_non_lone_vars"]


def test_second_pass(example_inputs):
    # Test non-disjoint
    example = example_inputs["simple"]
    first_pass = example["expected_outputs"]["first_pass"]
    ciphertext_polynomials = first_pass["ciphertext_polynomials"]
    key_non_lone_vars = first_pass["key_non_lone_vars"]
    ciphertext_non_lone_vars = first_pass["ciphertext_non_lone_vars"]
    key_polynomials_non_disjoint = example["failures"]["second_pass"][
        "key_polynomials_non_disjoint"
    ]
    with pytest.raises(ValueError) as excinfo:
        second_pass(
            key_polynomials_non_disjoint,
            ciphertext_polynomials,
            example["abenc"],
            key_non_lone_vars,
            ciphertext_non_lone_vars,
        )
    assert (
        str(excinfo.value)
        == "The input scheme is not a PES-ISA: master-key/semi-common variables and common variables are not disjoint."
    )

    for example in example_inputs.values():
        master_key_semi_common_vars, common_vars, unused_abenc_vars = second_pass(
            example["expected_outputs"]["first_pass"]["key_polynomials"],
            example["expected_outputs"]["first_pass"]["ciphertext_polynomials"],
            example["abenc"],
            example["expected_outputs"]["first_pass"]["key_non_lone_vars"],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
        )

        expected_output = example["expected_outputs"]["second_pass"]
        assert set(master_key_semi_common_vars) == set(
            expected_output["master_key_semi_common_vars"]
        )
        assert set(common_vars) == set(expected_output["common_vars"])
        assert set(unused_abenc_vars) == set(expected_output["unused_abenc_vars"])


def test_third_pass(example_inputs):
    # Test invalid ciphertext polynomial
    # example = example_inputs["simple"]
    # prepared_poly = prepare_polynomial_for_example(example)
    # first_pass = prepared_poly["expected_outputs"]["first_pass"]
    # second_pass = example["expected_outputs"]["second_pass"]
    # master_key_semi_common_vars = second_pass["master_key_semi_common_vars_s"]
    # common_vars = second_pass["common_vars_s"]
    # ciphertext_non_lone_vars = first_pass["ciphertext_non_lone_vars_s"]
    # unused_abenc_vars = second_pass["unused_abenc_vars_s"]
    # invalid_ciphertext_polynomials = [parse_expr(expr) for expr in example["cenc"]] + [
    #     parse_expr("A31*v3p + s3 * (b30 + x3 * alpha3)")
    # ]

    # with pytest.raises(ValueError) as excinfo:
    #     third_pass_parse_ciphertext_polynomials(
    #         invalid_ciphertext_polynomials,
    #         master_key_semi_common_vars,
    #         common_vars,
    #         ciphertext_non_lone_vars,
    #         unused_abenc_vars,
    #     )
    # assert (
    #     str(excinfo.value)
    #     == "The input scheme is not a PES-RVV: ciphertext polynomial does not satisfy the required form."
    # )

    for example in example_inputs.values():
        (
            ct_primed_poly,
            ct_non_primed_poly,
            ct_primed_lone_vars,
            ct_lone_vars,
        ) = third_pass_parse_ciphertext_polynomials(
            example["expected_outputs"]["first_pass"]["ciphertext_polynomials"],
            example["expected_outputs"]["second_pass"]["master_key_semi_common_vars"],
            example["expected_outputs"]["second_pass"]["common_vars"],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["second_pass"]["unused_abenc_vars"],
        )

        expected_output = example["expected_outputs"]["third_pass"]
        assert ct_primed_poly == expected_output["ciphertext_primed_polynomials"]
        assert (
            ct_non_primed_poly == expected_output["ciphertext_non_primed_polynomials"]
        )
        assert ct_primed_lone_vars == expected_output["ciphertext_primed_lone_vars"]
        assert ct_lone_vars == expected_output["ciphertext_lone_vars"]


# @pytest.mark.parametrize(
#     "invalid_input_key",
#     [
#         "master_key_semi_common_vars",
#         "key_non_lone_vars",
#         "key_polynomials",
#         "ciphertext_non_lone_vars",
#         "ciphertext_lone_vars",
#         "ciphertext_non_primed_polynomials",
#         "ciphertext_primed_polynomials",
#         "blinding_value",
#     ],
# )
# def test_invalid_inputs(example_inputs, invalid_input_key):
#     example = example_inputs["simple"]
#     inputs = {
#         "master_key_semi_common_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["second_pass"][
#                 "master_key_semi_common_vars"
#             ]
#         ],
#         "common_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["second_pass"]["common_vars"]
#         ],
#         "unused_abenc_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["second_pass"]["unused_abenc_vars"]
#         ],
#         "key_polynomials": [parse_expr(expr) for expr in example["kenc"]],
#         "key_non_lone_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["first_pass"]["key_non_lone_vars"]
#         ],
#         "key_lone_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["first_pass"]["key_lone_vars"]
#         ],
#         "ciphertext_primed_polynomials": [
#             parse_expr(expr)
#             for expr in example["expected_outputs"]["third_pass"][
#                 "ciphertext_primed_polynomials"
#             ]
#         ],
#         "ciphertext_non_primed_polynomials": [
#             parse_expr(expr)
#             for expr in example["expected_outputs"]["third_pass"][
#                 "ciphertext_non_primed_polynomials"
#             ]
#         ],
#         "ciphertext_non_lone_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["first_pass"][
#                 "ciphertext_non_lone_vars"
#             ]
#         ],
#         "ciphertext_primed_lone_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["third_pass"][
#                 "ciphertext_primed_lone_vars"
#             ]
#         ],
#         "ciphertext_lone_vars": [
#             parse_expr(var)
#             for var in example["expected_outputs"]["third_pass"]["ciphertext_lone_vars"]
#         ],
#         "known_vars": [parse_expr(var) for var in example["known_vars"]],
#         "blinding_value": parse_expr(example["expected_outputs"]["blinding_value"]),
#     }

#     # Modify the input based on the invalid input key
#     if invalid_input_key == "master_key_semi_common_vars":
#         inputs["master_key_semi_common_vars"] += [parse_expr("b10")]
#         expected_error = "The input scheme is not a PES-RVV: master-key/semi-common variables and common variables are not disjoint."
#     elif invalid_input_key == "key_non_lone_vars":
#         inputs["key_lone_vars"] += [parse_expr("rgid")]
#         expected_error = "The input scheme is not a PES-RVV: key non-lone variables and key lone variables are not disjoint."
#     elif invalid_input_key == "key_polynomials":
#         inputs["key_polynomials"] += [parse_expr("alpha1 + rgid * (b10 + y1)")]
#         expected_error = "The input scheme is not a PES-RVV: key polynomial does not satisfy the required form."
#     elif invalid_input_key == "ciphertext_non_lone_vars":
#         inputs["ciphertext_lone_vars"] += [parse_expr("s1")]
#         expected_error = "The input scheme is not a PES-RVV: ciphertext non-lone variables and ciphertext lone variables are not disjoint."
#     elif invalid_input_key == "ciphertext_lone_vars":
#         inputs["ciphertext_primed_lone_vars"] += [parse_expr("v2p")]
#         expected_error = "The input scheme is not a PES-RVV: ciphertext lone variables and ciphertext primed lone variables are not disjoint."
#     elif invalid_input_key == "ciphertext_non_primed_polynomials":
#         inputs["ciphertext_non_primed_polynomials"] += [
#             parse_expr("A12*v2p + s1 * (b10 + alpha1)")
#         ]
#         expected_error = "The input scheme is not a PES-RVV: ciphertext non-primed polynomial does not satisfy the required form."
#     elif invalid_input_key == "ciphertext_primed_polynomials":
#         inputs["ciphertext_primed_polynomials"] += [
#             parse_expr("A11*stilde + A12*v2 + s1 * b10")
#         ]
#         expected_error = "The input scheme is not a PES-RVV: ciphertext primed polynomial or blinding value does not satisfy the required form."
#     elif invalid_input_key == "blinding_value":
#         inputs["blinding_value"] = parse_expr("alpha1 * rgid")
#         expected_error = "The input scheme is not a PES-RVV: ciphertext primed polynomial or blinding value does not satisfy the required form."

#     with pytest.raises(ValueError) as excinfo:
#         fourth_pass_validate_encodings(**inputs)
#     assert str(excinfo.value) == expected_error


def test_fourth_pass(example_inputs):
    for example in example_inputs.values():
        result = fourth_pass_validate_encodings(
            example["expected_outputs"]["second_pass"]["master_key_semi_common_vars"],
            example["expected_outputs"]["second_pass"]["common_vars"],
            example["expected_outputs"]["first_pass"]["key_polynomials"],
            example["expected_outputs"]["first_pass"]["key_non_lone_vars"],
            example["expected_outputs"]["first_pass"]["key_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_primed_polynomials"],
            example["expected_outputs"]["third_pass"][
                "ciphertext_non_primed_polynomials"
            ],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_primed_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_lone_vars"],
            example["expected_outputs"]["blinding_value"],
        )

        assert result == example["expected_outputs"]["fourth_pass"]["result"]


def test_setup_penc_vector(example_inputs):
    for example in example_inputs.values():
        penc, penc_prime = setup_penc_vector(
            example["expected_outputs"]["first_pass"]["key_polynomials"],
            example["expected_outputs"]["third_pass"][
                "ciphertext_non_primed_polynomials"
            ],
            example["expected_outputs"]["third_pass"]["ciphertext_primed_polynomials"],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["first_pass"]["key_non_lone_vars"],
        )

        assert penc == example["expected_outputs"]["penc"]


def test_decompose_penc_vector(example_inputs):
    for example in example_inputs.values():
        M, v_1, v_2, tv = decompose_penc(
            example["expected_outputs"]["penc"],
            example["expected_outputs"]["second_pass"]["master_key_semi_common_vars"],
            example["expected_outputs"]["second_pass"]["common_vars"],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["first_pass"]["key_non_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_primed_lone_vars"],
            example["expected_outputs"]["first_pass"]["key_lone_vars"],
            example["expected_outputs"]["blinding_value"],
        )

        assert M == example["expected_outputs"]["M"]
        assert v_1 == example["expected_outputs"]["v1"]
        assert v_2 == example["expected_outputs"]["v2"]
        assert tv == example["expected_outputs"]["tv"].T


def test_decompose_ciphertext_primed_polynomials(example_inputs):
    for example in example_inputs.values():
        v_c_prime, M_c_prime = decompose_ciphertext_primed_polynomials(
            example["expected_outputs"]["third_pass"]["ciphertext_primed_polynomials"],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_primed_lone_vars"],
            example["expected_outputs"]["second_pass"]["master_key_semi_common_vars"],
        )

        assert v_c_prime == example["expected_outputs"]["v_c_prime"]
        assert M_c_prime == example["expected_outputs"]["M_c_prime"]


def test_find_kernel_vector(example_inputs):
    for example in example_inputs.values():
        w_no_corruption = find_kernel_vector(
            example["expected_outputs"]["M"],
            example["expected_outputs"]["M_c_prime"],
            example["expected_outputs"]["v1"],
            example["expected_outputs"]["v2"],
            example["expected_outputs"]["tv"],
            example["kenc"],
            example["cenc"],
            example["known_vars"],
            set(),
        )
        assert w_no_corruption == example["expected_outputs"]["w"]
        if "corruptable_vars" in example:
            w_with_corruption = find_kernel_vector(
                example["expected_outputs"]["M"],
                example["expected_outputs"]["M_c_prime"],
                example["expected_outputs"]["v1"],
                example["expected_outputs"]["v2"],
                example["expected_outputs"]["tv"],
                example["kenc"],
                example["cenc"],
                example["known_vars"],
                example["corruptable_vars"],
            )
            assert w_with_corruption == example["expected_outputs"]["w_cor"]


def test_decompose_ciphertext_polynomials(example_inputs):
    for example in example_inputs.values():
        v_c, M_c = decompose_ciphertext_polynomials(
            example["expected_outputs"]["third_pass"][
                "ciphertext_non_primed_polynomials"
            ],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_lone_vars"],
            example["expected_outputs"]["second_pass"]["common_vars"],
        )

        assert v_c == example["expected_outputs"]["v_c"]
        assert M_c == example["expected_outputs"]["M_c"]


def test_construct_substitution_vectors(example_inputs):
    for example in example_inputs.values():
        sub_vectors = construct_substitution_vectors(
            example["expected_outputs"]["v_c"],
            example["expected_outputs"]["v1"],
            example["expected_outputs"]["v2"],
            example["expected_outputs"]["w"],
            example["expected_outputs"]["M_c"],
            example["expected_outputs"]["second_pass"]["common_vars"],
            example["expected_outputs"]["second_pass"]["master_key_semi_common_vars"],
            example["expected_outputs"]["first_pass"]["key_non_lone_vars"],
            example["expected_outputs"]["first_pass"]["key_lone_vars"],
            example["expected_outputs"]["first_pass"]["ciphertext_non_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_lone_vars"],
            example["expected_outputs"]["third_pass"]["ciphertext_primed_lone_vars"],
            example["corruptable_vars"]
        )
        sub_vectors = {str(key): value for key, value in sub_vectors.items()}
        assert sub_vectors == example["expected_outputs"]["substitution_vector"]


# def test_verify_substitution_vectors(example_inputs):
#     for example in example_inputs.values():
#         corruptable_vars = set()
#         known_vars_in_key = example["known_vars"]
#         known_vars_in_ciphertext = set()  # Update this based on the example

#         assert verify_substitution_vectors(
#             example["expected_outputs"]["substitution_vector"],
#             example["expected_outputs"]["first_pass"]["key_polynomials"],
#             example["expected_outputs"]["third_pass"]["ciphertext_non_primed_polynomials"],
#             example["expected_outputs"]["third_pass"]["ciphertext_primed_polynomials"],
#             example["expected_outputs"]["blinding_value"],
#             corruptable_vars,
#             known_vars_in_key,
#             known_vars_in_ciphertext,
#         ) == True


# def test_analyze(example_inputs):
#     for example in example_inputs.values():
#         substitution_vectors = analyze(
#             example["kenc"],
#             example["cenc"],
#             example["abenc"],
#             example["known_vars"],
#             example["corruptable_vars"],
#             example["expected_outputs"]["blinding_value"],
#         )
#         assert (
#             substitution_vectors == example["expected_outputs"]["substitution_vector"]
#         )

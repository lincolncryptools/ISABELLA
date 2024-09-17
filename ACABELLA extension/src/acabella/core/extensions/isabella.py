from sympy import (
    Mul,
    symbols,
    Matrix,
    zeros,
    degree,
    simplify,
    solve,
    Eq,
    lcm,
    linsolve,
    lambdify,
    sympify,
)
import re


def is_product(expr):
    return isinstance(expr, Mul)


def first_pass(kenc, cenc, abenc):
    key_non_lone_vars = []
    key_lone_vars = {}
    key_polynomials = []
    ciphertext_non_lone_vars = []
    ciphertext_polynomials = []

    for p in kenc:
        if (p.is_monomial and p.total_degree() > 1) or (not p.is_monomial):
            key_polynomials.append(p)
            terms = p.terms()
            degree_one_terms = [term for term in terms if sum(term[0]) == 1]
            degree_one_vars = [
                var
                for term in degree_one_terms
                for var, degree in zip(p.gens, term[0])
                if degree == 1 and var not in abenc
            ]
            temp = dict.fromkeys(degree_one_vars)
            key_lone_vars.update(temp)
        elif all(
            degree(p, gen=var) == 0 for var in abenc
        ):  # assuming it is specified as a monomial w/o coefficients
            key_non_lone_vars.append(list(p.free_symbols)[0])

    for p in cenc:
        if (p.is_monomial and p.total_degree() > 1) or (not p.is_monomial):
            ciphertext_polynomials.append(p)
        elif all(
            degree(p, gen=var) == 0 for var in abenc
        ):  # assuming it is specified as a monomial w/o coefficients
            ciphertext_non_lone_vars.append(list(p.free_symbols)[0])

    return (
        key_polynomials,
        key_non_lone_vars,
        list(key_lone_vars.keys()),
        ciphertext_polynomials,
        ciphertext_non_lone_vars,
    )


def second_pass(
    key_polynomials,
    ciphertext_polynomials,
    abenc,
    key_non_lone_vars,
    ciphertext_non_lone_vars,
):
    master_key_semi_common_vars = []
    common_vars = []
    potential_common_vars = []

    # Iterate over each key polynomial
    for p in key_polynomials:
        terms = p.terms()

        degree_one_terms = [term for term in terms if sum(term[0]) == 1]
        degree_one_vars = [
            var
            for term in degree_one_terms
            for var, degree in zip(p.gens, term[0])
            if degree == 1 and var in abenc
        ]
        for potential_mk in degree_one_vars:
            if not potential_mk in master_key_semi_common_vars:
                master_key_semi_common_vars.append(potential_mk)
        # master_key_semi_common_vars.extend(degree_one_vars)

        degree_two_terms = [term for term in terms if sum(term[0]) == 2]
        # Check if each degree 2 term has one variable from abenc and one from r
        for term in degree_two_terms:
            vars_in_term = [var for var, degree in zip(p.gens, term[0]) if degree == 1]
            abenc_var = next((var for var in vars_in_term if var in abenc), None)
            r_var = next(
                (var for var in vars_in_term if var in key_non_lone_vars), None
            )
            if abenc_var and r_var:
                if not abenc_var in common_vars:
                    common_vars.append(abenc_var)
            elif r_var:
                other_var = next((var for var in vars_in_term if var != r_var), None)
                potential_common_vars.append(other_var)

    for p in ciphertext_polynomials:
        terms = p.terms()
        degree_two_terms = [term for term in terms if sum(term[0]) == 2]
        for term in degree_two_terms:
            vars_in_term = [var for var, degree in zip(p.gens, term[0]) if degree == 1]
            r_var = next(
                (var for var in vars_in_term if var in ciphertext_non_lone_vars), None
            )
            if r_var:
                other_var = next((var for var in vars_in_term if var != r_var), None)
                if other_var in potential_common_vars:
                    if not other_var in common_vars:
                        common_vars.append(other_var)
    
    # Check if the master key/semi-common variables and common variables are disjoint
    if not set(master_key_semi_common_vars).isdisjoint(set(common_vars)):
        raise ValueError(
            "The input scheme is not a PES-ISA: master-key/semi-common variables and common variables are not disjoint."
        )

    # Find the unused abenc variables
    unused_abenc_vars = set(abenc) - (
        set(master_key_semi_common_vars) | set(common_vars)
    )

    return master_key_semi_common_vars, common_vars, list(unused_abenc_vars)


def third_pass_parse_ciphertext_polynomials(
    ciphertext_polynomials,
    master_key_semi_common_vars,
    common_vars,
    ciphertext_non_lone_vars,
    unused_abenc_vars,
):
    ciphertext_primed_polynomials = []
    ciphertext_non_primed_polynomials = []
    ciphertext_lone_vars = []
    ciphertext_primed_lone_vars = []
    unknown_vars = set(ciphertext_polynomials[0].gens)

    for polynomial in ciphertext_polynomials:
        is_primed = False
        is_non_primed = False
        temp_lone_vars = []
        for monomial in polynomial.as_expr().as_coefficients_dict():
            if is_product(monomial):
                non_lone_var_present = any(
                    arg in ciphertext_non_lone_vars for arg in monomial.args
                )
                master_key_semi_common_var_present = any(
                    arg in master_key_semi_common_vars for arg in monomial.args
                )
                common_var_present = any(arg in common_vars for arg in monomial.args)
                unused_abenc_var_present = any(
                    arg in unused_abenc_vars for arg in monomial.args
                )
                if non_lone_var_present:
                    if master_key_semi_common_var_present or unused_abenc_var_present:
                        is_primed = True
                    elif common_var_present:
                        is_non_primed = True
                else:
                    for var in monomial.args:
                        if var in unknown_vars:
                            if var not in ciphertext_non_lone_vars:
                                if var not in temp_lone_vars:
                                    temp_lone_vars.append(var)
            else:
                if not monomial in temp_lone_vars:
                    temp_lone_vars.append(monomial)

        if is_primed:
            for var in temp_lone_vars:
                if var not in ciphertext_primed_lone_vars:
                    ciphertext_primed_lone_vars.append(var)
        else:
            for var in temp_lone_vars:
                if var not in ciphertext_lone_vars:
                    ciphertext_lone_vars.append(var)

        if is_primed and not is_non_primed:
            ciphertext_primed_polynomials.append(polynomial)
        elif is_non_primed and not is_primed:
            ciphertext_non_primed_polynomials.append(polynomial)
        else:
            raise ValueError(
                "The input scheme is not a PES-ISA: ciphertext polynomial does not satisfy the required form."
            )

    return (
        ciphertext_primed_polynomials,
        ciphertext_non_primed_polynomials,
        ciphertext_primed_lone_vars,
        ciphertext_lone_vars,
    )


def fourth_pass_validate_encodings(
    master_key_semi_common_vars,
    common_vars,
    key_polynomials,
    key_non_lone_vars,
    key_lone_vars,
    ciphertext_primed_polynomials,
    ciphertext_non_primed_polynomials,
    ciphertext_non_lone_vars,
    ciphertext_primed_lone_vars,
    ciphertext_lone_vars,
    blinding_value,
):
    # Validate key encodings
    if not set(key_non_lone_vars).isdisjoint(set(key_lone_vars)):
        raise ValueError(
            "The input scheme is not a PES-ISA: key non-lone variables and key lone variables are not disjoint."
        )

    for polynomial in key_polynomials:
        for monomial in polynomial.as_expr().as_coefficients_dict():
            if is_product(monomial):
                # known_var_present = any(var in known_vars for var in monomial.args)
                master_key_semi_common_var_present = any(
                    var in master_key_semi_common_vars for var in monomial.args
                )
                non_lone_var_present = any(
                    var in key_non_lone_vars for var in monomial.args
                )
                common_var_present = any(var in common_vars for var in monomial.args)
                lone_var_present = any(var in key_lone_vars for var in monomial.args)

                if not (
                    (master_key_semi_common_var_present)
                    or (non_lone_var_present and common_var_present)
                    or (lone_var_present)
                ):
                    raise ValueError(
                        "The input scheme is not a PES-ISA: key polynomial does not satisfy the required form."
                    )

    # Validate ciphertext encodings
    if not set(ciphertext_non_lone_vars).isdisjoint(ciphertext_lone_vars):
        raise ValueError(
            "The input scheme is not a PES-ISA: ciphertext non-lone variables and ciphertext lone variables are not disjoint."
        )

    if not set(ciphertext_non_lone_vars).isdisjoint(ciphertext_primed_lone_vars):
        raise ValueError(
            "The input scheme is not a PES-ISA: ciphertext non-lone variables and ciphertext primed lone variables are not disjoint."
        )

    if not set(ciphertext_lone_vars).isdisjoint(ciphertext_primed_lone_vars):
        raise ValueError(
            "The input scheme is not a PES-ISA: ciphertext lone variables and ciphertext primed lone variables are not disjoint."
        )

    for polynomial in ciphertext_non_primed_polynomials:
        for monomial in polynomial.as_expr().as_coefficients_dict():
            if is_product(monomial):
                # known_var_present = any(var in known_vars for var in monomial.args)
                common_var_present = any(var in common_vars for var in monomial.args)
                non_lone_var_present = any(
                    var in ciphertext_non_lone_vars for var in monomial.args
                )
                lone_var_present = any(
                    var in ciphertext_lone_vars for var in monomial.args
                )

                if not (
                    (common_var_present and non_lone_var_present) or (lone_var_present)
                ):
                    raise ValueError(
                        "The input scheme is not a PES-ISA: ciphertext non-primed polynomial does not satisfy the required form."
                    )

    for polynomial in ciphertext_primed_polynomials + [blinding_value]:
        for monomial in polynomial.as_expr().as_coefficients_dict():
            if is_product(monomial):
                # known_var_present = any(var in known_vars for var in monomial.args)
                master_key_semi_common_var_present = any(
                    var in master_key_semi_common_vars for var in monomial.args
                )
                non_lone_var_present = any(
                    var in ciphertext_non_lone_vars for var in monomial.args
                )
                primed_lone_var_present = any(
                    var in ciphertext_primed_lone_vars for var in monomial.args
                )

                if not (
                    (master_key_semi_common_var_present and non_lone_var_present)
                    or (primed_lone_var_present)
                ):
                    raise ValueError(
                        "The input scheme is not a PES-ISA: ciphertext primed polynomial or blinding value does not satisfy the required form."
                    )

    return True


def setup_penc_vector(
    key_polynomials,
    ciphertext_non_primed_polynomials,
    ciphertext_primed_polynomials,
    ciphertext_non_lone_vars,
    key_non_lone_vars,
):
    p_enc = []
    p_enc_prime = []

    # Compute s_j * k_i for all s_j in s and k_i in k
    for s_j in ciphertext_non_lone_vars:
        for k_i in key_polynomials:
            product = s_j * k_i
            p_enc.append(product)
            p_enc_prime.append(("non-lone ct", s_j, "key poly", k_i))

    # Compute r_j * c_i for all r_j in r and c_i in c
    for r_j in key_non_lone_vars:
        for c_i in ciphertext_non_primed_polynomials:
            product = r_j * c_i
            p_enc.append(product)
            p_enc_prime.append(("non-lone key", r_j, "ct poly", c_i))

    # Add c'_i for all c'_i in c' to p_enc
    for c_prime_i in ciphertext_primed_polynomials:
        p_enc.append(c_prime_i)
        p_enc_prime.append(("primed ct", c_prime_i))

    return p_enc, p_enc_prime


def decompose_penc(
    p_enc,
    master_key_semi_common_vars,
    common_vars,
    ciphertext_non_lone_vars,
    key_non_lone_vars,
    ciphertext_lone_vars,
    ciphertext_primed_lone_vars,
    key_lone_vars,
    blinding_value,
):
    M = Matrix()
    v = []

    # Add monomials to v
    for alpha_j in master_key_semi_common_vars:
        for s_j_prime in ciphertext_non_lone_vars:
            v.append(alpha_j * s_j_prime)

    for s_tilde_j in ciphertext_primed_lone_vars:
        v.append(s_tilde_j)

    for r_j in key_non_lone_vars:
        for s_j_prime in ciphertext_non_lone_vars:
            for b_k in common_vars:
                v.append(r_j * s_j_prime * b_k)

    for r_j in key_non_lone_vars:
        for s_hat_j_prime in ciphertext_lone_vars:
            v.append(r_j * s_hat_j_prime)

    for r_hat_j in key_lone_vars:
        for s_j_prime in ciphertext_non_lone_vars:
            v.append(r_hat_j * s_j_prime)

    # Split v into v1 and v2
    v1 = v[
        : len(master_key_semi_common_vars) * len(ciphertext_non_lone_vars)
        + len(ciphertext_primed_lone_vars)
    ]

    v2 = v[
        len(master_key_semi_common_vars) * len(ciphertext_non_lone_vars)
        + len(ciphertext_primed_lone_vars) :
    ]

    # For each polynomial pi in penc, construct a vector Mi such that Mi · v⊺ = pi
    for i, p_i in enumerate(p_enc):
        M_i = zeros(1, len(v))
        for j, monomial in enumerate(v):
            coeff = p_i.as_expr().coeff(monomial)
            if coeff != 0:
                M_i[j] = coeff
        M = M.row_insert(i, M_i)

    # Decompose the blinding value c_M = tv · v^T
    tv = zeros(1, len(v))
    for i, monomial in enumerate(v):
        if monomial in blinding_value.as_expr().as_coefficients_dict():
            tv[0, i] = blinding_value.as_expr().as_coefficients_dict()[monomial]

    return M, Matrix(v1), Matrix(v2), tv


def find_kernel_vector(M, M_c_primed, v1, v2, tv, kenc, cenc, known_vars, corruptable_vars):
    # Compute the basis V for the kernel of M
    basis = M.nullspace()

    # Check if the kernel basis is empty
    if not basis:
        raise ValueError("The kernel of M is empty.")

    # Extract lists of known variables kvk and kvc that occur in the key and ciphertext encodings
    kvk = set()
    for p in kenc:
        kvk.update(p.free_symbols & known_vars)

    kvc = set()
    for p in cenc:
        kvc.update(p.free_symbols & known_vars)

    # Create a list of known variables kvknc that occurs in the key encodings but not in the ciphertext encodings
    kvknc = kvk - kvc

    # Remove denominators for each kernel vector
    for i, b in enumerate(basis):
        denoms = [
            entry.as_numer_denom()[1] for entry in b if entry.as_numer_denom()[1] != 1
        ]
        common_denominator = lcm(denoms) if len(denoms) > 1 else 1
        basis[i] = simplify(b * common_denominator)

    # Create a matrix V where each column is a vector in V
    basis_matrix = Matrix.hstack(*basis)
    
    # Create vector v from v1 + v2
    v = Matrix.vstack(v1, v2)

    if corruptable_vars is not None and len(corruptable_vars) > 0:
        # Create a list of indices I of v1 such that i ∈ I if the i-th entry of v' is associated with a corrupted variable
        I = [
            i
            for i, entry in enumerate(v)
            if any(var in entry.free_symbols for var in corruptable_vars)
        ]
        
        # Create a set V' of truncated vectors in V with respect to I
        V_prime = [Matrix([b[i] for i in I]) for b in basis]

        # Create a matrix V' where each column is a vector in V'
        V_prime_matrix = Matrix.hstack(*V_prime)

        # Compute a basis W for the kernel of V'
        W = V_prime_matrix.nullspace()

        # Compute the set of vectors W_cor = { V · w^T | w ∈ W }
        W_cor = [simplify(basis_matrix * w) for w in W]

        W_cor_matrix = Matrix.hstack(*W_cor)

        basis = W_cor
        basis_matrix = W_cor_matrix
    
    # Truncate the basis vectors to consider only the entries associated with v1
    trunc_basis = [Matrix(b[: len(v1)]) for b in basis]

    if M_c_primed is not None:
        # Compute a basis Vc' for Mc'
        M_c_primed_basis = M_c_primed.nullspace()
        M_c_primed_basis_matrix = Matrix.hstack(*M_c_primed_basis)

        # Create a matrix M_lc where each row corresponds to vectors in trunc_basis written as a
        # linear combination of vectors in Vc'
        M_lc = zeros(len(trunc_basis), len(M_c_primed_basis))
        for i, b in enumerate(trunc_basis):
            # Write each vector in the truncated basis as a linear combination of vectors in Vc'
            coeffs = symbols(f"c{i}0:{len(M_c_primed_basis)}")
            sol = linsolve((M_c_primed_basis_matrix, b), coeffs)
            if sol:
                # Extract coefficients from the solution
                sol = list(list(sol)[0])
                M_lc[i, :] = [sol]
            else:
                raise ValueError("No solution found.")
    else:
        M_lc = Matrix.hstack(*trunc_basis).T

    M_rref = M_lc.rref(pivots=False)

    # Remove all-zero rows in M_rref
    M_rref = Matrix(
        [
            M_rref.row(i)
            for i in range(M_rref.rows)
            if not all(x == 0 for x in M_rref.row(i))
        ]
    )

    M_rref_key_independent = []
    for i in range(M_rref.rows):
        row = M_rref.row(i)
        if not row.free_symbols.intersection(kvknc):
            M_rref_key_independent.append(row)
    M_rref = Matrix.vstack(*M_rref_key_independent)

    # Sort rows by ascending Hamming weight
    def hamming_weight(row):
        """Calculate the Hamming weight of a matrix row."""
        return sum(1 for element in row if element != 0)

    M_rref = Matrix(sorted(M_rref.tolist(), key=hamming_weight))

    def find_lin_comb_cols(matrix, target_vector):
        nr_of_columns = matrix.shape[1]
        sol_matrix = matrix.col_insert(nr_of_columns, -target_vector)
        kernel_sol_matrix = sol_matrix.nullspace()
        for kern_vec in kernel_sol_matrix:
            if kern_vec[-1] != 0:
                kern_vec = kern_vec / kern_vec[-1]
                sol_vec = kern_vec[:-1]
        # returns a linear combination of the columns - in column form
        return sol_vec

    W_cor_ki = []
    for i in range(M_rref.rows):
        row = M_rref.row(i)
        sol = find_lin_comb_cols(M_lc.T, row.T)
        if sol:
            # Calculate the new basis vector w_cor_ki
            w_cor_ki = simplify(basis_matrix * Matrix(sol))
            W_cor_ki.append(w_cor_ki)  # Append the new vector to the list

    for w in W_cor_ki:
        if tv.dot(w.T) != 0:
            return w
    return None


def decompose_ciphertext_polynomials(
    ciphertext_non_primed_polynomials,
    ciphertext_non_lone_vars,
    ciphertext_lone_vars,
    common_vars,
):
    v_c = []
    for s_j in ciphertext_non_lone_vars:
        for b_k in common_vars:
            v_c.append(s_j * b_k)
    for s_hat_j in ciphertext_lone_vars:
        v_c.append(s_hat_j)

    v_c = Matrix(v_c)

    M_c = Matrix()
    for i, p_i in enumerate(ciphertext_non_primed_polynomials):
        M_i = zeros(1, len(v_c))
        for j, monomial in enumerate(v_c):
            coeff = p_i.as_expr().coeff(monomial)
            if coeff != 0:
                M_i[j] = coeff
        M_c = M_c.row_insert(i, M_i)

    return v_c, M_c


def decompose_ciphertext_primed_polynomials(
    ciphertext_primed_polynomials,
    ciphertext_non_lone_vars,
    ciphertext_primed_lone_vars,
    master_key_semi_common_vars,
):
    if len(ciphertext_primed_polynomials) == 0:
        return None, None
    v_c_primed = []
    for s_j in ciphertext_non_lone_vars:
        for alpha_k in master_key_semi_common_vars:
            v_c_primed.append(s_j * alpha_k)
    for s_tilde_j in ciphertext_primed_lone_vars:
        v_c_primed.append(s_tilde_j)

    v_c_primed = Matrix(v_c_primed)

    M_c_primed = Matrix()
    for i, p_i in enumerate(ciphertext_primed_polynomials):
        M_i = zeros(1, len(v_c_primed))
        for j, monomial in enumerate(v_c_primed):
            coeff = p_i.as_expr().coeff(monomial)
            if coeff != 0:
                M_i[j] = coeff
        M_c_primed = M_c_primed.row_insert(i, M_i)

    return v_c_primed, M_c_primed


def construct_substitution_vectors(
    v_c,
    v1,
    v2,
    w,
    M_c,
    common_vars,
    master_key_semi_common_vars,
    key_non_lone_vars,
    key_lone_vars,
    ciphertext_non_lone_vars,
    ciphertext_lone_vars,
    ciphertext_primed_lone_vars,
    corruptable_vars
):
    substitution_vectors = {}
    kernel_basis = M_c.nullspace()
    v = Matrix.vstack(v1, v2)

    for i, b in enumerate(kernel_basis):
        # Find the first non-zero element and divide all elements by it
        first_non_zero_element = next((elem for elem in b if elem != 0), None)
        kernel_basis[i] = (
            simplify(b / first_non_zero_element) if first_non_zero_element else b
        )

    # Construct substitution vectors for s
    for i, var in enumerate(ciphertext_non_lone_vars):
        substitution_vectors[var] = zeros(len(ciphertext_non_lone_vars), 1)
        substitution_vectors[var][i] = 1

    # Construct substitution matrices for b
    for var in common_vars:
        if not var in corruptable_vars:
            # Find the indices where var occurs in v_c
            indices = [i for i, monomial in enumerate(v_c) if var in monomial.free_symbols]
    
            # Truncate and reorder the kernel basis vectors
            truncated_basis = [Matrix([b[i] for i in indices]) for b in kernel_basis]
    
            # TODO: Reorder
            reordered_basis = truncated_basis
    
            # Construct the substitution matrix
            substitution_vectors[var] = Matrix.hstack(*reordered_basis)
        else:
            # Set the substitution matrix for b to be all zeros if b is corrupted
            substitution_vectors[var] = zeros(len(ciphertext_non_lone_vars), len(kernel_basis))

    # Construct substitution vectors for ŝ
    for var in ciphertext_lone_vars:
        # Find the index where var occurs in v_c
        idx = 0
        for i, monomial in enumerate(v_c):
            if var in monomial.free_symbols:
                idx = i
                break

        # Construct the substitution vector
        substitution_vectors[var] = Matrix([v[idx] for v in kernel_basis]).T

    # Construct substitution vectors for master-key/semi-common variables
    for var in master_key_semi_common_vars:
        # Find the indices where var occurs in v
        indices = [i for i, monomial in enumerate(v1) if var in monomial.free_symbols]

        # TODO: Order the indices based on the ciphertext non-lone variables
        ordered_indices = indices

        # Construct the substitution vector
        substitution_vectors[var] = Matrix([w[i] for i in ordered_indices])

    # Construct substitution vectors for key lone vars
    for var in key_lone_vars:
        # Find the indices where var occurs in v
        indices = [
            i + len(v1) for i, monomial in enumerate(v2) if var in monomial.free_symbols
        ]

        # TODO: Order the indices based on the ciphertext non-lone variables
        ordered_indices = indices

        # Construct the substitution vector
        substitution_vectors[var] = Matrix([w[i] for i in ordered_indices])

    for var in ciphertext_primed_lone_vars:
        # Find the index where var occurs in v1
        idx = 0
        for i, monomial in enumerate(v1):
            if var in monomial.free_symbols:
                idx = i
                break

        # Construct the substitution value
        substitution_vectors[var] = w[idx]

    for var in key_non_lone_vars:
        # Find the indices where var occurs in v
        indices = [
            i + len(v1) for i, monomial in enumerate(v2) if var in monomial.free_symbols
        ]

        # TODO: Order the indices based on the monomials in v_c
        ordered_indices = indices

        # Construct the vector w_r_j
        w_r_j = Matrix([w[i] for i in ordered_indices])

        # Create the matrix V_c_r_j
        V_c_r_j = Matrix.hstack(*kernel_basis, -w_r_j)

        # Compute the kernel of V_c_r_j
        kernel_V_c_r_j = V_c_r_j.nullspace()

        # Find a vector v in the kernel such that the last entry is nonzero
        v = next((v for v in kernel_V_c_r_j if v[-1] != 0), None)

        if v is not None:
            # Divide all entries of v by the last entry and remove the last entry
            divided_v = v / v[-1]
            substitution_vectors[var] = Matrix(divided_v[:-1])
        else:
            raise ValueError(
                f"No suitable vector found in the kernel of V_c_r_j for variable {var}"
            )
    return substitution_vectors

# def evaluate_expression(poly, known_vars, subs_dict):
#     # expr = poly.as_expr()
#     symbols = list((poly.free_symbols - known_vars))
#     print(f"symbols: {symbols}")
#     matrix_func = lambdify(symbols, poly.as_expr(), modules="sympy")
#     subs_values = [subs_dict[symbol] for symbol in symbols]
#     result = simplify(matrix_func(*subs_values))
#     return result

# def verify_substitution_vectors(
#     substitution_vectors,
#     key_polynomials,
#     ciphertext_non_primed_polynomials,
#     ciphertext_primed_polynomials,
#     blinding_value,
#     corruptable_vars,
#     known_vars
# ):
#     # Step one: verifying the substitutions
#     assert blinding_value.as_expr().subs(substitution_vectors) != 0
#     for poly in (
#         key_polynomials
#         + ciphertext_non_primed_polynomials
#         + ciphertext_primed_polynomials
#     ):
#         # if poly == blinding_value:
#         #     assert poly.subs(substitution_vectors) != 0
#         # else:
#         print(f"poly: {poly.as_expr()}")
#         result = evaluate_expression(poly, known_vars, substitution_vectors)
#         print(f"result: {result}")
#         # assert poly.as_expr().subs(substitution_vectors) == 0

    # Step two: verifying the corrupted master-key/semi-common variables

    # Step three: verifying the common variables

    # Step four: verifying the key independence

    # return True

# def verify_substitution_vectors(
#     substitution_vectors,
#     key_polynomials,
#     ciphertext_non_primed_polynomials,
#     ciphertext_primed_polynomials,
#     blinding_value,
#     corruptable_vars,
#     known_vars_in_key,
#     known_vars_in_ciphertext,
# ):
#     # Step one: verifying the substitutions
#     assert blinding_value.as_expr().subs(substitution_vectors) != 0
#     for poly in (
#         key_polynomials
#         + ciphertext_non_primed_polynomials
#         + ciphertext_primed_polynomials
#     ):
#         # if poly == blinding_value:
#         #     assert poly.subs(substitution_vectors) != 0
#         # else:
#         print(f"poly: {poly.as_expr()}")
#         result = evaluate_expression(poly, known_vars_in_key, substitution_vectors)
#         print(f"result: {result}")
#         assert poly.as_expr().subs(substitution_vectors) == 0

#     # Step two: verifying the corrupted master-key/semi-common variables

#     # Step three: verifying the common variables

#     # Step four: verifying the key independence

#     return True


def analyze(kenc, cenc, abenc, known_vars, corruptable_vars, key):
    # First pass
    (
        key_polynomials,
        key_non_lone_vars,
        key_lone_vars,
        ciphertext_polynomials,
        ciphertext_non_lone_vars,
    ) = first_pass(kenc, cenc, abenc)

    # Second pass
    master_key_semi_common_vars, common_vars, unused_abenc_vars = second_pass(
        key_polynomials,
        ciphertext_polynomials,
        abenc,
        key_non_lone_vars,
        ciphertext_non_lone_vars,
    )

    # Third pass
    (
        ciphertext_primed_polynomials,
        ciphertext_non_primed_polynomials,
        ciphertext_primed_lone_vars,
        ciphertext_lone_vars,
    ) = third_pass_parse_ciphertext_polynomials(
        ciphertext_polynomials,
        master_key_semi_common_vars,
        common_vars,
        ciphertext_non_lone_vars,
        unused_abenc_vars,
    )

    # Fourth pass
    if not fourth_pass_validate_encodings(
        master_key_semi_common_vars,
        common_vars,
        key_polynomials,
        key_non_lone_vars,
        key_lone_vars,
        ciphertext_primed_polynomials,
        ciphertext_non_primed_polynomials,
        ciphertext_non_lone_vars,
        ciphertext_primed_lone_vars,
        ciphertext_lone_vars,
        key,
    ):
        raise ValueError(f"Encodings are invalid in ISABELLA compatible format")

    # Setup penc vector
    penc, penc_prime = setup_penc_vector(
        key_polynomials,
        ciphertext_non_primed_polynomials,
        ciphertext_primed_polynomials,
        ciphertext_non_lone_vars,
        key_non_lone_vars,
    )

    # Decompose penc
    M, v1, v2, tv = decompose_penc(
        penc,
        master_key_semi_common_vars,
        common_vars,
        ciphertext_non_lone_vars,
        key_non_lone_vars,
        ciphertext_lone_vars,
        ciphertext_primed_lone_vars,
        key_lone_vars,
        key,
    )

    # Find kernel vector
    v_c_prime, M_c_prime = decompose_ciphertext_primed_polynomials(
        ciphertext_primed_polynomials,
        ciphertext_non_lone_vars,
        ciphertext_primed_lone_vars,
        master_key_semi_common_vars,
    )
    w = find_kernel_vector(
        M,
        M_c_prime,
        v1,
        v2,
        tv,
        kenc,
        cenc,
        known_vars,
        corruptable_vars,
    )

    # Decompose ciphertext polynomials
    v_c, M_c = decompose_ciphertext_polynomials(
        ciphertext_non_primed_polynomials,
        ciphertext_non_lone_vars,
        ciphertext_lone_vars,
        common_vars,
    )

    # Construct substitution vectors
    substitution_vectors = construct_substitution_vectors(
        v_c,
        v1,
        v2,
        w,
        M_c,
        common_vars,
        master_key_semi_common_vars,
        key_non_lone_vars,
        key_lone_vars,
        ciphertext_non_lone_vars,
        ciphertext_lone_vars,
        ciphertext_primed_lone_vars,
        corruptable_vars
    )

    return substitution_vectors


def parse(kenc, cenc, abenc, known_vars, corruptable_vars, blinding_value):
    def extract_symbols(expressions):
        pattern = r"\b[a-zA-Z_][a-zA-Z0-9_]*\b"
        return set(re.findall(pattern, " ".join(expressions)))

    # Extract all symbols
    all_expressions = kenc + cenc
    all_symbols = extract_symbols(all_expressions) | set(abenc) | set(known_vars)

    # Identify known and unknown variables
    known_vars = set(known_vars)
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

    return (
        to_polynomials(kenc),
        to_polynomials(cenc),
        {symbols(var) for var in abenc},
        {symbols(var) for var in known_vars},
        {symbols(var) for var in corruptable_vars},
        sympify(blinding_value, locals=symbols_dict).as_poly(*unknown_vars_syms),
    )

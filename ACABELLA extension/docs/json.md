# JSON formats in ACABELLA

For the different tools and analysis types in ACABELLA, JSON files
are utililized as inputs. In this section we describe each input file
and format.

## JSON format for ABGW bridge

Transforming an scheme specified using the ACABELLA format into an
input for ABGW requires the following fields:

- scheme_id: This filed identifies the scheme with a label e.g. "yjr13".
- analysis: ABGW bridge input files are identified by the tag "abgw".
- k: List of key encodings.
- c: List of ciphertext encodings. 
- mpk: List of mpk encodings. 
- gp: List of global parameter encodings.
- key: Blinding value e.g. "a * s",
- unknown_vars:  List of unkown variables. 
- known_vars: List of known variables. 

An valid input file for transforming the specification of the YJR13 scheme
into a valid input for the ABGW tool is:

```json
{
    "scheme_id": "yjr13",
    "analysis": "abgw",
    "k": ["a * (1 / x1) + x2 * b + r * (b / bp)", "r * bp * (1 / x1)", "r * b"],
    "c": ["s", "s / bp"],
    "mpk": ["bp"],
    "gp": ["b"],
    "key" : "a * s",
    "unknown_vars" :  ["a", "r", "s", "b", "bp"],
    "known_vars" : ["x1", "x2"]
}
```

## JSON format for master key attacks

A master key attack requires the following parameters in the JSON input file:

- scheme_id: This filed identifies the scheme with a label e.g. "yjr13".
- analysis: Identified by the "master_key" tag.
- master_key: Master key identifier e.g. alpha.
- unknown_vars:  List of unkown variables. 
- corruption_model: corruption model for master key attacks.
- corruptable_vars: list of dictionarie entries including 
variable type and variable.
- MPK_CA: List of encodings that are part of the MPK of the CA 
- MPK_AA: List of encodings that are part of the MPK of the AA 
- MPK_vars: Variables that are part of the MPK tha could be involved in the attack
- GP_vars: List of global parameters involved in the attack.

An example input file for analyzing the possibility of master key attacks
could be:

```json
{
    "scheme_id": "cm14",
    "analysis": "master_key",
    "k": ["alpha + r * b", "r"],
    "master_key": "alpha",
    "unknown_vars" :  ["alpha", "b", "r"],
    "corruption_model" : "CA",
    "corruptable_vars": [
        { "type":"MPK_CA", "var":"b" }
         ],
    "MPK_CA": ["b"],
    "MPK_AA": [],
    "MPK_vars": [],
    "GP_vars": []
}
```

> **Note:**
> The `unknown_vars` list should remain static and related to the description
> of the scheme. That means, that even if we add corruptable variables
> entries in the `corruptable_vars` dictionary, we don't need to remove those
> variables from `unknown_vars`. The parser function that processes the JSON
> files will automatically removed those variables from `unknown_vars`
> during the analysis.
> Further, the `MPK_vars` list is related to those MPK encodings (either
> coming from the CA or an AA) that are involved in the attack. We
> must distinguish this list from `MPK_CA` and `MPK_AA` which are only
> descriptive.

## JSON format for decryption key attacks

A decryption key attack requires the following parameters in the JSON input file:

- scheme_id: This filed identifies the scheme with a label e.g. "yjr13".
- k: Key encodings.
- c: Ciphertext encodings.
- mpk:  List of mpk encodings.
- gp: List of global parameter encodings.
- key: blinding value.
- unknown_vars: List of unknown variables.
- corruption_model: Corruption model associated to the attack.
- corruptable_vars: List of dictionaries with the corruptable variable and its type.
- MPK_AAi: List of MPK encodings related to the second AAi for the AA_extended corruption model.
- misc_vars: Misc. variables involved in the attack obtained by corruption.
  
An example input file for analyzing the possibility of master key attacks
could be:

```json
{
    "scheme_id": "cm14",
    "analysis": "decryption",
    "k": ["(alpha_i + r) / b", "r"],
    "c": ["s * b", "s * b2"],
    "mpk": ["b"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha", "r", "s", "b"],
    "corruption_model": "AA_extended",
    "corruptable_vars": [
        { "type":"MPK_AAi", "var":"b2" }
         ],
    "MPK_AAi": ["b2"],
    "misc_vars": []
}
```

## JSON format for conditional attacks

TODO

```json
{
    "scheme_id": "jlww13",
    "analysis": "conditional",
    "k_fixed": ["alpha + r"],
    "k_indexed": ["att_mpk_group*indexed_enc_rp_1 + r", "indexed_enc_rp_1"],
    "c_fixed": [],
    "c_indexed": ["att_mpk_group*lambda_policy_share", "lambda_policy_share"],
    "indexed_vars_k": ["rp"],
    "indexed_vars_c": [],
    "unknown": ["alpha", "r", "s"]
}
```

## JSON format for security analysis

An AC17 security analysis requires the following parameters in the JSON input file:

- `scheme_id`: This filed identifies the scheme with a label e.g. "yjr13".
- `k`: Key encodings.
- `c`: Ciphertext encodings.
- `mpk`:  List of mpk encodings.
- `gp`: List of global parameter encodings.
- `key`: Blinding factor.
- `alpha`: Descriptin of alpha.
- `s`: Description of s.
- `unknown_vars`: List of unknown variables.
- `corruptable_vars`: List of variables obtained via corruption.

An example input file for analyzing the security of a scheme is:

```json
{
    "scheme_id": "bsw07",
    "analysis": "security",
    "k": ["(alpha + r)/b", "r + r0 * b0", "r0", "(alpha + rp)/b", "rp + r1 * b1", "r1"],
    "c": ["s*b", "s - sp", "(s - sp)*b0", "sp * b1", "sp"],
    "mpk": ["b", "b0", "b1", "1"],
    "key" : "alpha * s",
    "unknown_vars" :  ["alpha", "b", "b0", "b1", "r", "rp", "r0", "r1", "s", "sp"],
    "corruptable_vars": []
}
```

## JSON format for complete analysis

It also possible to prepare a JSON file that includes the
parameters to perform a security analysis followed by
master key and decryption attacks. In that case, it is
possible to use the following JSON input file:

```json
{
"scheme_id": "cm14",
"security":{
    "analysis": "security",
    "k": ["(alpha_i + r) / b", "r"],
    "c": ["s * b"],
    "mpk": ["b"],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "r", "s", "b"]
},
"master_key":{
    "analysis": "master_key",
    "k": ["(alpha_i + r) / b", "r"],
    "master_key": "alpha_i",
    "unknown_vars" :  ["alpha_i", "r", "s"],
    "corruption_model" : "AA",
    "corruptable_vars": [
        { "type":"MPK_AA", "var":"b" }
         ],    
    "MPK_CA": [],
    "MPK_AA": ["alpha_i", "b"],
    "MPK_vars": [],
    "GP_vars": []
    },
"decryption":{
    "analysis": "decryption",
    "k": ["(alpha_i + r) / b", "r"],
    "c": ["s * b", "s * b2"],
    "mpk": ["b"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "r", "s", "b"],
    "corruption_model": "AA_extended",
    "corruptable_vars": [
        { "type":"MPK_AAi", "var":"b2" }
         ],
    "MPK_AAi": ["b2"],
    "MPK_AAj": ["b"],
    "misc_vars": []
    }
}
```

### Logic for complete analysis

Of type "all" is based on the following logic:

1. Runs `security_analysis` - if it works out, then there’s no need to run the `analysis_trivial_and_collusion_security function`.
2. If it doesn’t work out, run `analysis_trivial_and_collusion_security`.
3. If the checks indicate there might be attacks, run master key and decryption attack analysis.

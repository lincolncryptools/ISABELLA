
# About corruption in master and decryption key attacks

## Internal structures for keeping track of corruption attacks

- `corruption_map`: Updated via `add_corruptable_var`, it keeps entries
of name, origin pairs, being the origin a type of corupted variable
in the `MasterKeyCorruptedVariable` enumeration.

## Utilization of corruption-based methods in master key attacks

In order to use the master key class for utilizing corruption,
the following steps should be followed:

1. Define the parameters and initialize the attack
based on master key to recover and  unknown variables:

```python
    alpha, r, b = sp.symbols("alpha, r, b")
    
    k0 = alpha + r * b
    k1 = r
    k = [k0, k1]

    corruptable_vars_from_CA = [b]

    master_key_attack = MasterKeyAttack()
    master_key_attack.init(alpha, k, [alpha, r, b])
```

2. Define the encodings that belong to the MPK/MSK pair
for the CA or AA involved in the attack:

```python
    # add CA master pair

    master_key_attack.add_mpk_CA(b)
    master_key_attack.add_msk_CA(alpha)
```

3. Set the corruption model:

```python
    # set corruption model

    master_key_attack.set_corruption_model(MasterKeyCorruptionModel.CA)
```

4. Add variables obtained by corruption using its origin according to the
`MasterKeyCorruptedVariable` Enum type:

```python
    # add corruptable variables 

    for var in corruptable_vars_from_CA:
        master_key_attack.add_corruptable_var(MasterKeyCorruptedVariable.MPK_CA, var)
```

## Utilization of variable names in corruption cases

In ACABELLA, we address a variety of setups in multi-authority designs e.g.
where multiple attribute authorities (AA) and central authorities (CA) are
involved.

In general, we consider that several AAs are involved and that they are identified
by the index `i` where a CA is not involved in the corruption model. That means
that master secret keys alpha that are part of the attribute authority, are now 
identified as alpha_i, that is, they belong to the attribute authority i.

Besides this, if the corruption model involves a CA, we identify a CA by the
index `i` and all the variables are related to that index.

Finally, if the corruption model involves CAs and AAs, CAs are identified by the index
`i` and the attribute authorities and their variables with the index `j`.

When using the classes defined in `core/master_key` and `core/decryption` this naming
procedure must be respected to match the output of the `format_encodings` method.

## Available functions for adding variables that belong to authorities

Where an attacker is able to compromise an authority via
corruption there are different variables that can be taken
into account when performing a master and/or a decryption
attack. 

These variables should be added to the list of encodings involving
in the attack.  This can be done via the following functions depending
on the type of variable:

- For master key attacks:
    * `add_corruptable_variable_from_CA`: for a single parameter.
    * `add_corruptable_variable_from_AA`: for a single parameter. We must note
  that this function and `add_corruptable_variable_from_CA` modify the unknown
  list by removing the supplied parameter, that is, making that parameter known.
    * `add_gp_variable`: for a global parameter.
    * `add_mpk`: for a master public key parameter.

- For decryption key attacks:
    * `add_corruptable_variable_from_AA`: for a single parameter.
    * `add_corruptable_variable_from_CA`: for a single parameter.
    * `add_mpk_variable`: for a master public key parameter.
    * `add_gp_variable`: for a global parameter.

## Corruption models in master key attacks

When analyzing the security a multi-authority ABE scheme, we distinguish
among the following corruption cases:

- `NoCorruption`: An attack can be performed without performing corruption of one 
of the authorities.
- `CA`: the unique central authority is corrupted and its sensitive parameters captured by an attacker.
- `AA`: Simple corruption of AAs. One attribute authority, `AA[i]` is corrupted and its sensitive parameters captured.
- `mixed_CA_corr`: the scheme consists of several authorities, CAs and AAs. However, we consider
the case where the CA has been corrupted.
- `mixed_AA_corr`: the scheme consists of several authorities, CAs and AAs. However, we consider
the case where the AA has been corrupted.

## Corruption models in decryption attacks

When analyzing the security a multi-authority ABE scheme, we distinguish
among the following corruption cases for decryption attacks:

- `NoCorruption`: An attack can be performed without performing corruption of one 
of the authorities.
- `AA`: One attribute authority, `AA[i]` is corrupted and its sensitive parameters captured.
- `AA_extended`: One attribute authority, `AA[i]` is corrupted and its sensitive parameters captured. However, interacction with a different `AA[j]` where `j` and `i` are different is required to finish the attack. The rationale here is that different attribute-independent encodings `c_i`, `c_j` for `i != j` must be obtained for the attack.

## A note about simulating corruption in security checks

It is possible to use the `"corruptable_vars": []` field in the JSON input to add possible variables captured via corruption during the security analysis of an ABE scheme.


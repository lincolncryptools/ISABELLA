
`ACABELLA` provides different functions and classes for analyzing
the security of ABE schemes.

## Classes for finding attacks in ABE schemes

The base class for finding attacks is the
`Attack` class:

::: acabella.core.cryptanalysis.attack

### Master key attacks

::: acabella.core.cryptanalysis.master_key

### Decryption key attacks

::: acabella.core.cryptanalysis.decryption

## Classes for analyzing the security of ABE schemes

::: acabella.core.cryptanalysis.analysis

## JSON parsing of ACABELLA parameters

::: acabella.core.common.parse_config

## Methods for generating indexed encodings and specific access structures

::: acabella.core.common.access_structures

## Methods for working with Sympy symbols

::: acabella.core.common.utils

## Methods for generating general encodings

::: acabella.core.common.encodings

## Methods for proof generation

::: acabella.core.proof.proof_generation

## Methods for proof verification

::: acabella.core.proof.proof_verification

## Methods for checking if an ABE scheme is correct according to the AC17 framework

::: acabella.core.proof.ac17_correctness_checks

## Security analysis methods

::: acabella.core.proof.security_analysis_ac17

## Main security proof methods

::: acabella.core.proof.security_proof

## Trivial security and collusion checks

::: acabella.core.proof.trivial_security_and_collusion

## Security class for performing security checks on ABE schemes

::: acabella.core.proof.security

## Functions for checking the FABEO property

::: acabella.core.proof.FABEO_properties
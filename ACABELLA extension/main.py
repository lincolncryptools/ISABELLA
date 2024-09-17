import argparse
import json
from acabella.core.extensions.isabella import analyze, parse
from sympy import pprint


def main():
    parser = argparse.ArgumentParser(
        description="ISABELLA Substitution Vector Generator"
    )
    parser.add_argument("input_file", help="Path to the input JSON file")
    parser.add_argument("-o", "--output", help="Path to the output JSON file")
    args = parser.parse_args()

    # Load the input JSON file
    with open(args.input_file, "r") as file:
        input_data = json.load(file)

    # Extract the required data from the input
    kenc, cenc, abenc, known_vars, corruptable_vars, key = parse(
        input_data["k"],
        input_data["c"],
        input_data["mpk"],
        input_data["known_vars"],
        input_data["corruptable_vars"],
        input_data["key"],
    )

    # Run the RVV functions
    substitution_vectors = analyze(kenc, cenc, abenc, known_vars, corruptable_vars, key)

    # Print the substitution vectors
    print("Substitution Vectors:")
    pprint(substitution_vectors)

    # Save the substitution vectors to a JSON file if output path is provided
    if args.output:
        with open(args.output, "w") as file:
            json.dump({str(key): str(value) for key, value in substitution_vectors.items()}, file, indent=2)


if __name__ == "__main__":
    main()

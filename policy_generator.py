#!/usr/bin/env python3

from os import read, write
import yaml, argparse, sys

read_exceptions = []
write_exceptions = []
allow_all_writes = False
allow_all_reads = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a policy file based on the input parameters.")
    parser.add_argument("out_file", help="Output Policy File.")
    parser.add_argument("--allow_all_reads", action='store_true', help="Use the flag to allow all reads. Default : deny ")
    parser.add_argument("--allow_all_writes", action='store_true', help="Use the flag to allow all writes. Default : deny ")
    parser.add_argument("--exception", action="append", nargs="+", help="List of read and write exceptions to the the default access provided.")
    parser.add_argument("--reuse", nargs="+", help="Resuse existing policies from the existing policy files.")
    args = parser.parse_args()

    out_file = args.out_file
    policy_files = args.reuse
    exceptions = args.exception
    read_default = args.allow_all_reads
    write_default = args.allow_all_writes

    # Parse input policy files and get the read and write exceptions
    # for the default permissions
    if policy_files is not None:
        for file in policy_files:
            with open(file, "r") as stream:
                try:
                    parsed = yaml.load(stream, Loader=yaml.FullLoader)

                    if allow_all_writes is True and parsed["DefaultRead"] == "deny":
                        continue

                    if allow_all_reads is True and parsed["DefaultWrite"] == "deny":
                        continue

                    if parsed["DefaultRead"] == "allow":
                        allow_all_reads = True
                        read_exceptions = []

                    if parsed["DefaultWrite"] == "allow":
                        allow_all_writes = True
                        write_exceptions = []

                    read_exceptions.extend(parsed["Exceptions"]["R"])
                    write_exceptions.extend(parsed["Exceptions"]["W"])

                except yaml.YAMLError as exc:
                    print(exc)


    if exceptions:
        # Parse read and write exceptions from commandline.
        for el in exceptions:
            for e in el:
                if '=' in e:
                    oplist = e.split("=")
                    if oplist[0].lower() == "r":
                        read_exceptions.extend([exception.rstrip('/').replace("*",".*")+"$" for exception in oplist[1].split(',')])
                    elif oplist[0].lower() == "w":
                        write_exceptions.extend([exception.rstrip('/').replace("*",".*")+"$" for exception in oplist[1].split(',')])
                    else:
                        print("Invalid Input!!")
                        sys.exit(0)
                else:
                    print("Invalid Input!!")
                    sys.exit(0)

    print("Allow All Reads - " + str(read_default))
    print("Allow All Writes - " + str(write_default))
    print("read expectations - " + str(read_exceptions))
    print("write expectations - " + str(write_exceptions))

    # Create a dictionary representation for YAML output.
    data = dict(
        DefaultRead = "allow" if read_default is True else "deny",
        DefaultWrite = "allow" if write_default is True else "deny",
        Exceptions = dict(
            R = list(set(read_exceptions)),
            W = list(set(write_exceptions))
        )
    )

    # Dump the YAML output to a file.
    with open(out_file, 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)

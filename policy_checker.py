#!/usr/bin/env python3

import yaml
from flask import Flask
import flask
import re
import os

# Check for the file permission of the input file with the available policies.
def check_file(allow_all_reads, allow_all_writes, write_exceptions, read_exceptions, input, flag=None, mode=None):
    WRONLY = 0x0001
    RDWR = 0x0002
    CREAT = 0x0200
    TRUNC = 0x0400

    WRITE_FLAG = WRONLY | RDWR | CREAT | TRUNC

    modes = ["rb", "r+", "rb+", "w", "wb", "w+", "wb+", "a", "ab", "a+", "ab+"]

    f1 = lambda x,y,z: z if re.match(x,y) != None else not z

    write_operation = False if (flag & WRITE_FLAG) == 0 else True
    if not (mode == None or mode == ""):
        write_operation = write_operation | (mode in modes)

    if write_operation:
        if allow_all_writes:
            return f1(write_exceptions, input, False)
        else:
            return f1(write_exceptions, input, True)
    else:
        if allow_all_reads:
            return f1(read_exceptions, input, False)
        else:
            return f1(read_exceptions, input, True)


app = Flask(__name__)

@app.route('/check')
def get_product():
    write_exceptions = []
    read_exceptions = []
    allow_all_writes = False
    allow_all_reads = False
    parsed_args = {}
    parsed_args['Policy'] = flask.request.headers.get('Policy')
    parsed_args['Path'] = flask.request.headers.get('Path')
    parsed_args['Flags'] = flask.request.headers.get('Flags')
    parsed_args['Mode'] = flask.request.headers.get('Mode')
    parsed_args['Cwd'] = flask.request.headers.get('Cwd').rstrip('/') if flask.request.headers.get('Cwd') else ""

    input_file = parsed_args['Path']

    if not input_file.startswith('/'):
        input_file = parsed_args['Cwd'] + '/' + parsed_args['Path']

    policy_files = parsed_args['Policy'].split(",")

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

                write_exceptions.extend([exception for exception in parsed["Exceptions"]["W"]])
                read_exceptions.extend(write_exceptions)
                read_exceptions.extend([exception for exception in parsed["Exceptions"]["R"]])
                write_exceptions = "|".join(write_exceptions) if write_exceptions else "$^"
                read_exceptions = "|".join(read_exceptions) if read_exceptions else "$^"

            except yaml.YAMLError as exc:
                print(exc)

    if (check_file(allow_all_reads, allow_all_writes, write_exceptions, read_exceptions, input_file, int(parsed_args['Flags']), parsed_args['Mode'])):
        return "",200
    else:
        return "",404


app.run(host='0.0.0.0', port=8081, debug=False)

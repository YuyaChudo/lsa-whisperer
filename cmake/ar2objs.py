#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2025 Evan McBroom

'''Extract all object files in an archive.'''

import arpy
import os
import sys

if len(sys.argv) > 2 and os.path.isfile(sys.argv[1]) and os.path.isdir(sys.argv[2]):
    with arpy.Archive(sys.argv[1]) as archive:
        if type(archive) == arpy.Archive:
            for file in archive:
                fileName = os.path.split(file.header.name)[-1]
                if os.path.splitext(fileName)[1] in [b'.o', b'.obj']:
                    outputName = os.path.splitext(fileName)[0] + b'.o'
                    with open(os.path.join(sys.argv[2].encode(), outputName), 'wb') as outputFile:
                        outputFile.write(file.read())
        else:
            print("The specified path is not a valid archive file.", file=sys.stderr)
else:
    print("{} <archive path> <output directory>", sys.argv[0], file=sys.stderr)

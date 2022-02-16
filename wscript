# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

def build(bld):
    obj = bld.create_ns3_program('interfacemanager-nb-example', ['interfacemanager-nb'])
    obj.source = 'interfacemanager-nb-example.cc'
    obj.includes = [obj.includes, '/home/doutorado/ns-allinone-3.30.1/ns-3.30.1/src/interfacemanager-nb/examples']


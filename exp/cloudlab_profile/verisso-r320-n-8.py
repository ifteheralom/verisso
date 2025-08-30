"""Cloudlab profile of r320 experiment with 8 nodes.

Instructions:
Use this profile to run the experiment on Cloudlab.
"""

node_count = 8
node_type = "r320"

import geni.portal as portal
import geni.rspec.emulab as emulab
import geni.rspec.pg as rspec

request = portal.context.makeRequestRSpec()

interfaces = []

for i in range(node_count):
    i = i
    node = request.RawPC("node" + str(i))
    node.hardware_type = node_type

    # # Create an interface for each node
    iface = node.addInterface("eth" + str(i))
    interfaces.append(iface)

# Link
link = request.Link("link")
link.Site("undefined")

for iface in interfaces:
    link.addInterface(iface)

# Print the RSpec
portal.context.printRequestRSpec(request)

#from netaddr import IPAddress
p4 = bfrt.vQueues.pipe

fwd_table = p4.SwitchIngress.forward

vq_table = p4.SwitchIngress.getQueueLimit


fwd_table.add_with_send(dst_addr = IPAddress('192.168.0.20'), port = 160, id = 5)

vq_table.add_with_qLimit(qID = 5, qLimit = 10)

bfrt.complete_operations()
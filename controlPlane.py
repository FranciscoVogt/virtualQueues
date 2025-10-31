from netaddr import IPAddress
p4 = bfrt.vQueues.pipe

fwd_table = p4.SwitchIngress.forward

vq_table = p4.SwitchIngress.getQueueLimit


fwd_table.add_with_send(dst_addr = IPAddress('192.168.0.9'), port = 132, id = 5)

fwd_table.add_with_send(dst_addr = IPAddress('192.168.0.7'), port = 133, id = 6)

fwd_table.add_with_send(dst_addr = IPAddress('192.168.0.4'), port = 134, id = 7)

vq_table.add_with_qLimit(qID = 5, limit = 100)
vq_table.add_with_qLimit(qID = 6, limit = 500)
vq_table.add_with_qLimit(qID = 7, limit = 1000)

bfrt.complete_operations()
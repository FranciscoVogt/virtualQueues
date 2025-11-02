# Virtual Queues on P4 Switches

Repository with preliminary implementation of virtual queues in Tofino 1.

Initial design:
<img width="2355" height="588" alt="vQueues1 0" src="https://github.com/user-attachments/assets/2d6bf331-1fcc-443e-96e3-1ba9ea7a29df" />

## Usage
To test the code, you just need to clone the repository, set the SDE bash, and run the `run.sh` script.

If you need to configure different configurations, you need to edit the files `portConfigs` and `controlPlane` to add your specific port configurations and table entries. In the `controlPlane` you can configure both the routing and the virtualQueues. The queue limit parameter defines how many packets are allowed to pass the queue each second.

## Monitoring and statistics

To enable easy measurements and evaluations, we include a monitoring block on the egress pipeline. This block contains a byte counter for all active flows and ports. For the flows, we use the CRC 32 hash (truncated to 12 bits) to store the flow information. Then, you can send probe packets to collect this information, and show in real time (or store in a CSV file).

The folder `hostScripts` has our monitoring script (AI generated) to send probe packets, receive it back, and show/store the information.

Example of usage:
```
sudo python3 monitor_throughput.py --mode both --send-if enp6s0f0 --recv-if enp6s0f1 --file instruc.txt
```

> **Parameters:**

| Parameter   | Default      | Description                                                                                                                                                                                                                                                                                                     |
| ----------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--mode`    | `both`       | Defines the operation mode. Options: <br>• `both` — send and receive packets simultaneously (local testing) <br>• `sender` — only sends monitoring packets based on the input file <br>• `receiver` — only listens and displays throughput statistics                                                           |
| `--send-if` | `enp6s0f0`   | Network interface used to send monitoring packets.                                                                                                                                                                                                                                                              |
| `--recv-if` | `enp6s0f1`   | Network interface used to receive monitoring packets and telemetry data.                                                                                                                                                                                                                                        |
| `--file`    | *(required)* | Path to the configuration file that defines the monitoring flows to be created. Example format: <br>`\nflow=499, port=172, period=0.5\n#flow=1000, port=200, period=1.0\n` <br>Each line defines one flow, with `period` controlling how often packets are sent (seconds). Lines starting with `#` are ignored. |
| `--log`     | *(optional)* | Enables CSV logging of all received monitoring packets. Each log entry includes: flow ID, port ID, byte counters, timestamp, queue IDs, queue depths, and queue times. The log file is named automatically with a timestamp.                                                                                    |
| `--dst-mac` | *(optional)* | Overrides the default MAC address resolution. If set, packets will be sent directly to this MAC address, avoiding broadcast warnings.                                                                                                                                                                           |
| `--refresh` | `1.0`        | Refresh interval (in seconds) for the dashboard update.                                                                                                                                                                                                                                                         |
| `--timeout` | `5.0`        | Inactive timeout (in seconds). Flows or ports not receiving updates for more than this time are removed from the dashboard display.                                                                                                                                                                             |


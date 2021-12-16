# Python script to check for Log4j bad actors using vRealize Network Insight

This python script downloads a public CSV file filled with IPs of bad actors that are trying to abuse the Log4j vulnerability. Then it uses the vRealize Network Insight APIs to check whether any connection attempts have been made in the network that vRNI monitors.

CSV file with IPs: https://gist.github.com/blotus/f87ed46718bfdc634c9081110d243166

## Prerequisites

* Tested with python3
* [vRealize Network Insight Python SDK](https://github.com/vmware/network-insight-sdk-python)
* Run `pip3 install -r requirements.txt` to install any requirements you might not have

## Usage

This is how to run the script:

```
# export PYTHONPATH=/your/path/tp/network-insight-sdk-python/swagger_client-py2.7.egg
# python3 vrni-log4j-flow-check.py --platform_ip pre-ga.vrni.cmbu.local --username toolkit@local.com --password $VRNI_PW
```

If you are running this on the [vRealize Network Insight Toolkit](https://flings.vmware.com/vrealize-network-insight-toolkit), the Python SDK and PYTHONPATH will already be set: all you have to do is download the script onto the Toolkit and run it using above command.

## Example

![example output](https://github.com/vrealize-network-insight/vrni-log4j-flow-check/raw/12b8df01073f22a2c166a97e6a0714e92ed3144c/example/example.gif)

# QoE Monitoring VNF for HTTP Adaptive Video Streaming

<b> QoE Monitoring with VNFs in the Cloud </b>

# Required: <i> libtins-master </i>

libtins is a high-level, multiplatform C++ network packet sniffing and 
crafting library. Its main purpose is to provide the C++ developer an easy, efficient, 
platform and endianess-independent way to create tools which need to 
send, receive and manipulate specially crafted packets.
In order to read tutorials, examples and checkout some benchmarks of the
library, please visit:

http://libtins.github.io/

# Compiling 

[libtins](http://libtins.github.io/) depends on 
[libpcap](http://www.tcpdump.org/) and 
[openssl](http://www.openssl.org/), although the latter is not necessary if some features of the library are disabled.

In order to compile the funtion, execute:

# Create the build directory
mkdir build <br />
cd build <br />

# Configure the function. Add any relevant configuration flags
cmake .. <br />

# Compile!
make

# Running tests
sudo ./live_moni [replication] [number_of_clients] [Ethernet_port]

# Homepage
<a href = "https://go.uniwue.de/qoevnf"> https://go.uniwue.de/qoevnf </a>


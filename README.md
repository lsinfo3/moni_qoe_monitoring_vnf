# QoE Monitoring VNF for HTTP Adaptive Video Streaming

<b> QoE Monitoring with VNFs in the Cloud </b>

<b> Required: </b> <i> libtins-master </i>

libtins is a high-level, multiplatform C++ network packet sniffing and 
crafting library. Its main purpose is to provide the C++ developer an easy, efficient, 
platform and endianess-independent way to create tools which need to 
send, receive and manipulate specially crafted packets.
In order to read tutorials, examples and checkout some benchmarks of the
library, please visit:

http://libtins.github.io/

<b> Compiling </b>

[libtins](http://libtins.github.io/) depends on 
[libpcap](http://www.tcpdump.org/) and 
[openssl](http://www.openssl.org/), although the latter is not necessary if some features of the library are disabled.

In order to compile the funtion, execute:

<b> Create the build directory </b>
mkdir build <br />
cd build <br />

<b> Configure the function. Add any relevant configuration flags
cmake .. <br />

<b> Compile! </b>
make

<b> Running tests </b>
You would need root privilege to run the function
sudo ./live_moni [replication] [number_of_clients] [Ethernet_port]

<b> Homepage </b>
<a href = "https://go.uniwue.de/qoevnf"> https://go.uniwue.de/qoevnf </a>


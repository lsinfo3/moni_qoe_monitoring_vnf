# QoE Monitoring VNF for HTTP Adaptive Video Streaming

<b> QoE Monitoring with VNFs in the Cloud </b>
The VNF QoE monitoring is a plain software that exploits a C++ library, namely <i>libtins</i> to capture the video flows at network interface. The captured packets are then parsed to feed all necessary information for the video buffer estimation algorithm, such as IP address, TCP header and the payload of application layer protocols.

<b> Sniffing task required: </b> <i> libtins-master </i>

libtins is a high-level, multiplatform C++ network packet sniffing and 
crafting library. Its main purpose is to provide the C++ developer an easy, efficient, 
platform and endianess-independent way to create tools which need to 
send, receive and manipulate specially crafted packets.
In order to read tutorials, examples and checkout some benchmarks of the
library, please visit:

http://libtins.github.io/

<b> Compiling </b>

[libtins](http://libtins.github.io/) depends on  <br />
[libpcap](http://www.tcpdump.org/) and  <br />
[openssl](http://www.openssl.org/), although the latter is not necessary if some features of the library are disabled. <br />

In order to compile the funtion, execute: <br />

<b> Create the build directory </b> <br />
mkdir build <br />
cd build <br />

<b> Configure the function. Add any relevant configuration flags
cmake .. <br />

<b> Compile! </b> <br />
make

<b> Running sniffing tests </b> <br />
You would need root privilege to run the function
sudo ./live_moni [replication] [number_of_clients] [Ethernet_port]

<b> References </b> <br />
Please refer to following publication for more details:

Dinh-Xuan, L., Seufert, M., Wamser, F., Tran-Gia, P. "Study on the Accuracy of QoE Monitoring for HTTP Adaptive Video Streaming Using VNF". 1st IFIP/IEEE International Workshop on Quality of Experience Management (QoE-Management), Lisbon, Portugal (2017).

<b> Homepage </b> <br />
<a href = "https://go.uniwue.de/qoevnf"> https://go.uniwue.de/qoevnf </a>


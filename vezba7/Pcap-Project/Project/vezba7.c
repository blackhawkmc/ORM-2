// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: vezba7.c
// ================================================================

// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"

int packet_counter = 0;

// Function declarations
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
pcap_if_t* select_device(pcap_if_t *devices);
void print_ethernet_header(ethernet_header *eh);
void print_ip_header(ip_header *ih);
void print_tcp_header(tcp_header *th);
void print_udp_header(udp_header *uh);
void print_application_data(unsigned char *data, long data_length);
void print_raw_data(unsigned char *data, int data_length);

int main()
{
    pcap_if_t *devices;
    pcap_if_t *device;
    pcap_t *device_handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned int netmask;
    char filter_exp[] = "ether src host b8:27:eb:3c:83:83 and ip and (tcp or udp)";
    struct bpf_program fcode;

    int result;							// result of pcap_next_ex function
    int packet_counter = 0;				// counts packets in order to have numerated packets
    struct pcap_pkthdr *packet_header;	// header of packet (timestamp and length)
    const unsigned char *packet_data;	// packet content
    int res = 0;

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    // Chose one device from the list
    device = select_device(devices);

    // Check if device is valid
    if (device == NULL)
    {
        pcap_freealldevs(devices);
        return -1;
    }

    // Open the capture device
    if ((device_handle = pcap_open_live(device->name,		// name of the device
        65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
        1,							// promiscuous mode
        2000,						// read timeout
        error_buffer				// buffer where error message is stored
    )) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
        pcap_freealldevs(devices);
        return -1;
    }

    // Check the link layer. We support only Ethernet for simplicity.
    if (pcap_datalink(device_handle) != DLT_EN10MB)
    {
        printf("\nThis program works only on Ethernet networks.\n");
        return -1;
    }

#ifdef _WIN32
    if (device->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;
#else
    if (!device->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;
#endif

    // Compile the filter
    if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
    {
        printf("\n Unable to compile the packet filter. Check the syntax.\n");
        return -1;
    }

    // Set the filter
    if (pcap_setfilter(device_handle, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return -1;
    }

    printf("\nListening on %s...\n", device->description);

    // At this point, we don't need any more the device list. Free it
    pcap_freealldevs(devices);


	 /* Open the output device */
    /*if ( (device_handle=pcap_open_live(device->name,            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        1,  // promiscuous mode
                        1000,               // read timeout
                        NULL,               // authentication on the remote machine
                        error_buffer              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
        return;
    }

    u_char packet[100];
    int i;

    //Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1
    packet[0]=0xb8;
    packet[1]=0x27;
    packet[2]=0xeb;
    packet[3]=0x26;
    packet[4]=0x2e;
    packet[5]=0x94;

    //Set mac source to 2:2:2:2:2:2
    packet[6]=0xb8;
    packet[7]=0x27;
    packet[8]=0xeb;
    packet[9]=0x3c;
    packet[10]=0x83;
    packet[11]=0x83;

    //Fill the rest of the packet
    for(i=12;i<100;i++)
    {
        packet[i]=(u_char)i;
    }

    //Send down the packet
    if (pcap_sendpacket(device_handle, packet, 100 // size ) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(device_handle));
        return;
    }*/


    // Start the capture
    pcap_loop(device_handle, 5, packet_handler, NULL);

}

// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data)
{
    unsigned int i;
    // Print timestamp and length of the packet
    time_t timestamp;			// Raw time (bits) when packet is received
    struct tm *local_time;		// Local time when packet is received
    char time_string[16];		// Local time converted to string
    ethernet_header *eh;
    ip_header *ih;
    int ip_len;
    unsigned char *app_data;
    long data_len;

    printf("\n=============================================================");
    printf("\nPacket (%d): %s, %d byte\n", ++packet_counter, time_string, packet_header->len);
    // Convert the timestamp to readable format
    timestamp = packet_header->ts.tv_sec;
    local_time = localtime(&timestamp);
    strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);

    eh = (ethernet_header *)packet_data;
    print_ethernet_header(eh);

    ih = (ip_header*)(packet_data + sizeof(ethernet_header));
    print_ip_header(ih);
    ip_len = ih->header_length * 4; // header length is calculated using words (1 word = 4 bytes)

    // udp
    if (ih->next_protocol == 0x11)
    {
        udp_header *uh = (udp_header*) ((unsigned char*)ih + ip_len);
        print_udp_header(uh);
        app_data = (unsigned char*)uh + sizeof(udp_header);
        data_len = ntohs(uh->datagram_length);
    }
    // tcp
    else if (ih->next_protocol == 0x6)
    {
        tcp_header *th = (tcp_header*) ((unsigned char*)ih + ip_len);
        print_tcp_header(th);
        app_data = (unsigned char*)th + th->header_length * 4;
        data_len = packet_header->len - (th->header_length * 4 + ih->header_length * 4 + sizeof(ethernet_header));
    }
    else
    {
        return;
    }

    print_application_data(app_data, data_len);

    printf("\n=============================================================\n");

}

// This function provide possibility to chose device from the list of available devices
pcap_if_t* select_device(pcap_if_t *devices)
{
    int device_number;
    int i = 0;	// Count devices and provide jumping to the selected device
    pcap_if_t *device;

    // Print the list
    for (device = devices; device; device = device->next)
    {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return NULL;
    }

    // Pick one device from the list
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &device_number);

    if (device_number < 1 || device_number > i)
    {
        printf("\nInterface number out of range.\n");
        return NULL;
    }

    // Jump to the selected device
    for (device = devices, i = 0; i< device_number - 1; device = device->next, i++);

    return device;
}

// Print raw data of headers and applications
void print_raw_data(unsigned char *data, int data_length)
{
    int i;
	printf("\n-------------------------------------------------------------\n\t");
	for(i = 0; i < data_length; i=i+1)
	{
		printf("%.2x ", ((unsigned char*)data)[i]);

		// 16 bytes per line
		if ((i+1) % 16 == 0)
			printf("\n\t");
	}
	printf("\n-------------------------------------------------------------");
}

//Print content of Ethernet header
void print_ethernet_header(ethernet_header *eh)
{
    printf("\n=============================================================");
    printf("\n\tDATA LINK LAYER  -  Ethernet");

    printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->dest_address[0], eh->dest_address[1], eh->dest_address[2], eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);

    printf("\n=============================================================");
}

void print_ip_header(ip_header *ih)
{
    printf("\n=============================================================");
    printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");

    printf("\n\tDestination address:\t\t%u.%u.%u.%u", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);
}

void print_tcp_header(tcp_header *th)
{
    printf("\n=============================================================");
    printf("\n\tTRANSPORT LAYER  -  Transmission Control Protocol (TCP)");

    printf("\n\tDestination port:\t%u", ntohs(th->dest_port));

    printf("\n=============================================================");
}

void print_udp_header(udp_header *uh)
{
    printf("\n=============================================================");
    printf("\n\tTRANSPORT LAYER  -  User Datagram Protocol (UDP)");

    printf("\n\tDestination port:\t%u", ntohs(uh->dest_port));

    printf("\n=============================================================");
}

void print_application_data(unsigned char *data, long data_length)
{
	printf("\n=============================================================");
	printf("\n\tAPPLICATION DATA");

	print_raw_data(data, data_length);

	printf("\n=============================================================");
}

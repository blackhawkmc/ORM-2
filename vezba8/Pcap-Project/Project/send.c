#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>


void main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    int i;
    pcap_if_t *devices;
    pcap_if_t *device;
    pcap_t *device_handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned int netmask;

    /* Check the validity of the command line 
    if (argc != 2)
    {
        printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        return;
    }*/

     /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return;
    }

    // Chose one device from the list
    device= select_device(devices);

    // Check if device is valid
    if (device == NULL)
    {
        pcap_freealldevs(devices);
        return;
    }

    
    /* Open the output device */
    if ( (device= pcap_open(argv[1],            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        1,  // promiscuous mode
                        1000,               // read timeout
                        NULL,               // authentication on the remote machine
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
        return;
    }

    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=0xb8;
    packet[1]=0x27;
    packet[2]=0xeb;
    packet[3]=0x26;
    packet[4]=0x2e;
    packet[5]=0x94;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=0xb8;
    packet[7]=0x27;
    packet[8]=0xeb;
    packet[9]=0x3c;
    packet[10]=0x83;
    packet[11]=0x83;
    
    /* Fill the rest of the packet */
    for(i=12;i<100;i++)
    {
        packet[i]=(u_char)i;
    }

    /* Send down the packet */
    if (pcap_sendpacket(device, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        return;
    }

    return;
}
#include "odr_header.h"
uint32_t ephemeral_port_no_seed;
/* state time for routing table entry */
uint32_t stale_time;
/* head of interface list*/
struct hwa_info* hwa_info_list_head;
/* canonical IP address of host running ODR */
char host_canonical_ip[128];
/* head of peer list */
struct peer* peer_list_head;
/* head of the routing table*/
struct routing_table_entry* head_routing_tab_entry;
/* head of pending payload list*/
struct pending_app_payload_list* pending_payload_list_head;
/* head of already rcvd ODR route request */
struct rcvd_odr_rrequest_list* rcvd_rreq_list_head;
/* BROADCAST ID seed */
uint32_t rreq_broadcast_id;
/* head of already rcvd ODR route reply */
struct rcvd_odr_rrep_list* rcvd_rrep_list_head;
/* head of pending RREP list */
struct pending_odr_rrep_list *pending_rrep_list_head;

/********************************ODR related functions********************************/
void gen_interface_list();

int add_peer(char *sun_path, uint16_t port, uint16_t is_port_well_known);

void remove_stale_peers();

void process_peer_comm_data(char* dest_canonical_ip_ptr, uint16_t dest_port, char* msg, int force_route_discovery, struct sockaddr_un peer_sock_addr, int pf_sock_fd);

struct odr_app_payload* prepare_app_payload(char* dest_canonical_ip_ptr, uint16_t dest_port, uint16_t source_port, char* msg, size_t msg_len);

struct odr_rrequest* prepare_odrrequest(char* dest_canonical_ip_ptr, uint16_t force_route_discovery, uint16_t rrep_already_sent);

struct routing_table_entry* get_routing_table_entry(char* dest_canonical_ip_ptr);

void remove_routing_table_entry(char* dest_canonical_ip_ptr);

void update_routing_table_entry(struct routing_table_entry new_route_tab_entry);

void remove_stale_routing_tab_entry();

void add_payload_to_pending_list(struct odr_app_payload *payload);

void broadcast_odr_rreq(int pf_sock_fd, struct odr_rrequest rreq, int excluded_if_index);

struct ethernet_frame* prepare_ethernet_frame(unsigned char* dest_mac, unsigned char* source_mac, union ethernet_payload);

void update_rcvd_rreq_list(struct ethernet_frame* rreq);

struct hwa_info* get_hwa_info(int if_index);

void send_ethernet_frame(int pf_sock_fd, unsigned char* dest_mac, struct hwa_info* hw_if, struct ethernet_frame* eth_frame, uint16_t packet_type);

void process_rcvd_ethernet_frame(int pf_sock_fd, int domain_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame);

void process_rcvd_odr_rreq(int pf_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame);

void process_rcvd_odr_rrep(int pf_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame);

void process_rcvd_odr_app_payload(int pf_sock_fd, int domain_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame);

struct ethernet_frame* get_rcvd_rreqs(char* originator_canonical_ip_ptr);

void update_rcvd_rrep_list(struct ethernet_frame* rrep);

struct ethernet_frame* get_rcvd_rreps(char* originator_canonical_ip_ptr, char* dest_canonical_ptr);

void process_pending_rreps(int pf_sock_fd, struct routing_table_entry *dest_route_entry);

void process_pending_app_payloads(int pf_sock_fd, struct routing_table_entry *dest_route_entry);

void add_rrep_to_pending_list(struct odr_rreply *rrep);

struct peer* get_peer(uint16_t port);
/********************************ODR related functions********************************/


int main(int argc, char* argv[])
{
    /* General variable*/
    fd_set rset;
    int max_fd;

    /* peer communication variable*/
    int domain_sock_fd;
    struct sockaddr_un peer_sock_addr;
    struct sockaddr_un odr_sock_addr;
    struct peer_comm_data peer_rcvd_data;
    socklen_t unix_domain_sock_addr_len;

    /* routing commnication variable */
    int pf_sock_fd;
    struct sockaddr_ll remote_sock_addr;
    struct hwa_info* temp_hwa_info;
    void* eth_padded_frame;
    socklen_t pf_sock_addr_len;
    struct ethernet_frame rcvd_eth_frame;
    struct ethernet_frame *rcvd_eth_frame_ptr;
    /*Intialize global parameters */
    ephemeral_port_no_seed = 1;

    head_routing_tab_entry = NULL;

    pending_payload_list_head = NULL;

    rreq_broadcast_id = 1;

    rcvd_rreq_list_head = NULL;

    rcvd_rrep_list_head = NULL;

    pending_rrep_list_head = NULL;
    if(argc != 2)
    {
        fprintf(stdout, "\nPlease enter correct input: staleness parameter missing\n");
        exit(1);
    }

    /* Get the staleness time */
    stale_time = 0;
    stale_time = atoi(argv[1]);


    /* Initialize and bind ODR unix domain socket address*/
    memset(&odr_sock_addr, 0, sizeof(struct sockaddr_un));

    /* remove previous linkage; not required as such link will be closed in the end*/
    unlink(ODR_SUN_PATH);

    odr_sock_addr.sun_family = AF_UNIX;
    strcpy(odr_sock_addr.sun_path, ODR_SUN_PATH);

    if((domain_sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
    {
        fprintf(stdout, "Error creating UNIX domain socket: %s\n", strerror(errno));
        exit(1);
    }

    if(bind(domain_sock_fd, (struct sockaddr*)(&odr_sock_addr), sizeof(struct sockaddr_un)) < 0)
    {
        fprintf(stdout, "Error binding UNIX domain socket: %s\n", strerror(errno));
        exit(1);
    }

    /* Prepare pf_socket for remote host communication*/
    if((pf_sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ODR_PROTOCOL_ID))) < 0 )
    {
        fprintf(stderr, "Error creating PF_SOCKET:%s\n", strerror(errno));
        unlink(ODR_SUN_PATH);
        exit(1);
    }

    /* Get information about all interfaces except etho0 and loopback*/
    hwa_info_list_head = NULL;
    gen_interface_list();

    if(hwa_info_list_head == NULL)
    {
        fprintf(stdout, "No hardware address information available\n");
        unlink(ODR_SUN_PATH);
        exit(1);
    }

    /*Get canonical IP address of the host running ODR*/
    memset(host_canonical_ip, 0, sizeof(host_canonical_ip));
    temp_hwa_info = hwa_info_list_head;
    while(temp_hwa_info != NULL)
    {
        if( strcmp(temp_hwa_info->if_name, "eth0") == 0 && temp_hwa_info->ip_alias != 1)
        {
            strcpy(host_canonical_ip, sock_ntop(temp_hwa_info->ip_addr, sizeof(*temp_hwa_info->ip_addr)));
            fprintf(stdout, "Host canonical IP:%s\n", host_canonical_ip);
            break;
        }
        temp_hwa_info = temp_hwa_info->hwa_next;
    }

    /* add server to peer table */
    peer_list_head = NULL;
    add_peer(SERVER_SUN_PATH, SERVER_PORT, 1);


    while(1)
    {
        FD_ZERO(&rset);
        FD_SET(domain_sock_fd, &rset);
        FD_SET(pf_sock_fd, &rset);
        max_fd = (domain_sock_fd > pf_sock_fd ? domain_sock_fd: pf_sock_fd) + 1;
        //fprintf(stdout, "Waiting to receive request from peer\n");

        if(select(max_fd, &rset, NULL, NULL, NULL) < 0)
        {
            fprintf(stderr, "Error while select:%s\n", strerror(errno));
            unlink(ODR_SUN_PATH);
            exit(1);
        }

        /* message received from peer */
        if(FD_ISSET(domain_sock_fd, &rset))
        {
            memset(&peer_rcvd_data, 0, sizeof(struct peer_comm_data));
            memset(&peer_sock_addr, 0, sizeof(struct sockaddr_un));
            unix_domain_sock_addr_len = sizeof(struct sockaddr_un);

            if(recvfrom(domain_sock_fd, &peer_rcvd_data, sizeof(struct peer_comm_data), 0, (struct sockaddr*)&peer_sock_addr, &unix_domain_sock_addr_len) < 0)
            {
                fprintf(stderr, "Error while receiving data from peer on UNIX domain socket:%s\n",strerror(errno));
                unlink(ODR_SUN_PATH);
                exit(1);
            }
            /* process received peer communincation data */
            process_peer_comm_data(peer_rcvd_data.canonical_ip, peer_rcvd_data.port, peer_rcvd_data.msg, peer_rcvd_data.force_route_discovery, peer_sock_addr, pf_sock_fd);
        }

        if(FD_ISSET(pf_sock_fd, &rset))
        {
            pf_sock_addr_len = sizeof(struct sockaddr_ll);

            memset(&remote_sock_addr, 0, sizeof(struct sockaddr_ll));
            memset(&rcvd_eth_frame, 0, sizeof(struct ethernet_frame));
            //rcvd_eth_frame_ptr = (struct ethernet_frame*)malloc(sizeof(struct ethernet_frame));
            //memset(rcvd_eth_frame_ptr, 0 , sizeof(struct ethernet_frame));

            if(recvfrom(pf_sock_fd, &rcvd_eth_frame, sizeof(struct ethernet_frame) , 0, (struct sockaddr*)&remote_sock_addr, &pf_sock_addr_len) < 0)
            {
                fprintf(stderr, "Error while receiving data from peer on PF socket:%s\n",strerror(errno));
                unlink(ODR_SUN_PATH);
                exit(1);
            }

            //fprintf(stdout, "Received Message type: %d\n", ntohs(rcvd_eth_frame.payload.info.odr_msg_type));
            //fprintf(stdout, "Received Message broadcast ID: %u\n", ntohl(rcvd_eth_frame.payload.rreq.broadcast_id));
            //fprintf(stdout, "Interface Index: %d\n", remote_sock_addr.sll_ifindex);

            /* process received ethernet frame */


            process_rcvd_ethernet_frame(pf_sock_fd, domain_sock_fd, remote_sock_addr, rcvd_eth_frame);
        }

    }
    /* delete the file before leaving*/
    unlink(ODR_SUN_PATH);
    return 0;
}

/*******************************start of gen_interface_list function*************************/
    void gen_interface_list()
    {
        hwa_info_list_head = Get_hw_addrs();
        struct hwa_info * temp_hwa_info = hwa_info_list_head;
        while(temp_hwa_info != NULL)
        {
            printf("Interface name: %s, interface index: %d\n", temp_hwa_info->if_name, temp_hwa_info->if_index);
            temp_hwa_info = temp_hwa_info->hwa_next;
        }
    }
/*******************************end of gen_interface_list function*************************/


/*******************************start of add_peer function*************************/
    int add_peer(char *sun_path, uint16_t port, uint16_t is_port_well_known)
    {
        struct peer* temp_peer_ptr;
        struct peer* peer_data_ptr;

        /* First check if peer is already avialable */
        if(peer_list_head == NULL)
        {
            /* peer is not available; prepare new entry */
        }
        else
        {
            temp_peer_ptr = peer_list_head;

            while(temp_peer_ptr != NULL)
            {
                /* if entry already exists */
                if(strcmp(temp_peer_ptr->sun_path, sun_path) == 0)
                {
                    gettimeofday(&temp_peer_ptr->entry_time, NULL);

                    return temp_peer_ptr->port;
                }
                temp_peer_ptr = temp_peer_ptr->next_peer;
            }
        }

        /* Prepare new entry */
        peer_data_ptr = (struct peer*)malloc(sizeof(struct peer));

        memset(peer_data_ptr, 0, sizeof(struct peer));

        peer_data_ptr->next_peer = NULL;
        peer_data_ptr->port = port;
        strcpy(peer_data_ptr->sun_path, sun_path);
        peer_data_ptr->is_port_well_known = is_port_well_known;

        /* purging required if port is not well known, fill time of insertion*/
        if(peer_data_ptr->is_port_well_known == 0)
        {
            gettimeofday(&peer_data_ptr->entry_time, NULL);
        }

        /* message */
        fprintf(stdout, "New peer has been added with path: %s\n", peer_data_ptr->sun_path);

        if(peer_list_head == NULL)
        {
            peer_list_head = peer_data_ptr;
            return peer_data_ptr->port;
        }

        temp_peer_ptr = peer_list_head;
        /* Get the last peer in the list */
        while(temp_peer_ptr->next_peer != NULL)
        {
            temp_peer_ptr = temp_peer_ptr->next_peer;
        }

        temp_peer_ptr->next_peer = peer_data_ptr;
        return peer_data_ptr->port;
    }
/*******************************end of add_peer function*************************/



/*******************************start of process_peer_comm_data function*************************/
void process_peer_comm_data(char* dest_canonical_ip_ptr, uint16_t dest_port, char* msg, int force_route_discovery, struct sockaddr_un peer_sock_addr, int pf_sock_fd)
{
    uint16_t peer_port;
    struct routing_table_entry *temp_routing_tab_entry = NULL;
    struct timeval current_time;
    struct odr_app_payload* new_app_payload;
    struct odr_rrequest* temp_odr_rreq;
    struct hwa_info* temp_hwa_info;
    struct ethernet_frame* temp_eth_frame;
    /* First process peer table corresponding to incoming peer communication data */
    /* remove stale entries */
    remove_stale_peers();

    /* add/update the  current client in the peer table */
    ephemeral_port_no_seed++;
    peer_port = add_peer(peer_sock_addr.sun_path, ephemeral_port_no_seed, 0);

    /* if entry already exist, revert ephemeral_port_no_seed to older value */
    if(peer_port != ephemeral_port_no_seed)
        ephemeral_port_no_seed--;

    /* prepare ethernet payload */
    new_app_payload = prepare_app_payload(dest_canonical_ip_ptr, dest_port, peer_port, msg, strlen(msg));

    /* check for routing table entry*/
    temp_routing_tab_entry = get_routing_table_entry(dest_canonical_ip_ptr);
    /* check routing entry's staleness, if stale remove routing table entry OR if remove routing table entry if force_route_discovery is set */
    gettimeofday(&current_time, NULL);

    if(temp_routing_tab_entry != NULL)
    {
        if( (force_route_discovery == 1) || (stale_time < ((current_time.tv_sec + current_time.tv_usec/1000) - (temp_routing_tab_entry->entry_time.tv_sec + temp_routing_tab_entry->entry_time.tv_usec/1000) )) )
        {
            remove_routing_table_entry(dest_canonical_ip_ptr);
            temp_routing_tab_entry = NULL;
        }
    }


    /* if no valid routing table entry found, trigger RREQ */
    if(temp_routing_tab_entry == NULL)
    {
        /* first keep current peer msg payload into pending payload list*/
        add_payload_to_pending_list(new_app_payload);

        /* prepare route request message */
        temp_odr_rreq = prepare_odrrequest(dest_canonical_ip_ptr, force_route_discovery, 0);

        /* broadcast the ODR route request message */
        broadcast_odr_rreq(pf_sock_fd, *temp_odr_rreq, -1);
    }
    else /*send unicast message directly to destination through a neigbour */
    {
        /* prepare ethernet frame with message to be sent*/
        temp_hwa_info = get_hwa_info(temp_routing_tab_entry->if_index);
        temp_eth_frame = prepare_ethernet_frame(temp_routing_tab_entry->neighbour_mac, (unsigned char*)temp_hwa_info->if_haddr, (union ethernet_payload)(*new_app_payload));
        send_ethernet_frame(pf_sock_fd, temp_routing_tab_entry->neighbour_mac, temp_hwa_info, temp_eth_frame, PACKET_OTHERHOST);
    }

}
/*******************************end of process_peer_comm_data function*************************/



/*******************************start of remove_stale_peers function*************************/
void remove_stale_peers()
{
    struct peer* temp_peer = peer_list_head;
    struct peer* prev_temp_peer = NULL;
    struct timeval current_time;

    /* Get current to derive the staleness */
    gettimeofday(&current_time, NULL);

    while(temp_peer != NULL)
    {
        if(temp_peer->is_port_well_known == 1)
        {
            /* do nothing */
        }
        else
        {
            if(PEER_STALENESS_TIME < ( (current_time.tv_sec - temp_peer->entry_time.tv_sec) + (current_time.tv_usec - temp_peer->entry_time.tv_usec)/1000000 ) )
            {
                /* message */
                fprintf(stdout, "Removing stale peer with path: %s\n", temp_peer->sun_path);

                if(prev_temp_peer != NULL)
                {
                    prev_temp_peer->next_peer = temp_peer->next_peer;
                    free(temp_peer);
                    temp_peer = prev_temp_peer->next_peer;
                }
                else /* if previous pointer is NULL, then current pointer refers to head */
                {
                    peer_list_head = temp_peer->next_peer;
                    free(temp_peer);
                    temp_peer = peer_list_head;
                }

                continue;
            }
        }
        prev_temp_peer = temp_peer;
        temp_peer = temp_peer->next_peer;
    }
}
/*******************************end of remove_stale_peers function*************************/

/*******************************start of prepare_app_payload function*************************/
struct odr_app_payload* prepare_app_payload(char* dest_canonical_ip_ptr, uint16_t dest_port, uint16_t source_port, char* msg, size_t msg_len)
{
    struct odr_app_payload* new_payload = (struct odr_app_payload*)(malloc(sizeof(struct odr_app_payload)));

    strcpy(new_payload->dest_canonical_ip, dest_canonical_ip_ptr);
    strcpy(new_payload->source_canonical_ip, host_canonical_ip);
    strcpy(new_payload->msg, msg);
    new_payload->dest_port = htons(dest_port);
    new_payload->source_port = htons(source_port);
    new_payload->msg_length = htonl(msg_len);
    new_payload->hop_count = htonl(1);
    new_payload->odr_msg_type = htons(2);

    return new_payload;
}
/*******************************end of prepare_app_payload function*************************/

/*******************************start of prepare_odrrequest function*************************/
struct odr_rrequest* prepare_odrrequest(char* dest_canonical_ip_ptr, uint16_t force_route_discovery, uint16_t rrep_already_sent)
{
    struct odr_rrequest* temp_rreq = (struct odr_rrequest*)malloc(sizeof(struct odr_rrequest));

    temp_rreq->broadcast_id = htonl(rreq_broadcast_id++);
    strcpy(temp_rreq->dest_canonical_ip, dest_canonical_ip_ptr);
    strcpy(temp_rreq->originator_canonical_ip,host_canonical_ip);
    temp_rreq->force_route_discovery = htons(force_route_discovery);
    temp_rreq->hop_count = htons(1);
    temp_rreq->odr_msg_type = htons(0);
    temp_rreq->rrep_already_sent = htons(rrep_already_sent);

    return temp_rreq;
}
/*******************************end of prepare_odrrequest function*************************/

/*******************************start of get_routing_table_entry function*************************/
struct routing_table_entry* get_routing_table_entry(char* dest_canonical_ip_ptr)
{
    struct routing_table_entry *temp_routing_tab_entry;

    temp_routing_tab_entry = head_routing_tab_entry;

    while(temp_routing_tab_entry != NULL)
    {
        if(strcmp(dest_canonical_ip_ptr, temp_routing_tab_entry->dest_canonical_ip) == 0)
            break;

        temp_routing_tab_entry = temp_routing_tab_entry->next_entry;
    }

    return temp_routing_tab_entry;
}
/*******************************start of get_routing_table_entry function*************************/

/*******************************start of remove_routing_table_entry function*************************/
void remove_routing_table_entry(char* dest_canonical_ip_ptr)
{
    struct routing_table_entry* temp_routing_tab_entry = head_routing_tab_entry;
    struct routing_table_entry* prev_temp_rout_tab_entry = NULL;

    while(temp_routing_tab_entry != NULL)
    {
        if(strcmp(temp_routing_tab_entry->dest_canonical_ip, dest_canonical_ip_ptr) == 0)
        {
            if(prev_temp_rout_tab_entry != NULL)
            {
                prev_temp_rout_tab_entry->next_entry = temp_routing_tab_entry->next_entry;
            }
            else /*routing table head is being removed */
            {
                head_routing_tab_entry = temp_routing_tab_entry->next_entry;
            }
            /* message */
            fprintf(stdout, "Deleting routing entry for destination canonical IP: %s\n", dest_canonical_ip_ptr);
            free(temp_routing_tab_entry);
            break;
        }
        temp_routing_tab_entry = temp_routing_tab_entry->next_entry;
    }
}
/*******************************end of remove_routing_table_entry function*************************/

/*******************************start of add_payload_to_pending_list function*************************/
void add_payload_to_pending_list(struct odr_app_payload *payload)
{
    struct pending_app_payload_list * temp_payload_list_node;
    struct pending_app_payload_list* new_payload_list_node;
    struct odr_app_payload *new_payload;

    new_payload_list_node = (struct pending_app_payload_list*)malloc(sizeof(struct pending_app_payload_list));
    new_payload = (struct odr_app_payload*)malloc(sizeof(struct odr_app_payload));
    memcpy(new_payload, payload, sizeof(struct odr_app_payload));
    new_payload_list_node->payload = new_payload;
    new_payload_list_node->next_pending_payload = NULL;

    if(pending_payload_list_head == NULL)
    {
        pending_payload_list_head = new_payload_list_node;
    }
    else
    {
        temp_payload_list_node = pending_payload_list_head;

        while(temp_payload_list_node->next_pending_payload != NULL)
        {
            temp_payload_list_node = temp_payload_list_node->next_pending_payload;
        }
        temp_payload_list_node->next_pending_payload = new_payload_list_node;
    }

}
/*******************************end of add_payload_to_pending_list function*************************/



/*******************************start of broadcast_odr_rreq function*************************/
void broadcast_odr_rreq(int pf_sock_fd, struct odr_rrequest rreq, int excluded_if_index)
{
    struct hwa_info *temp_hwa_info;
    struct ethernet_frame* temp_eth_frame;
    unsigned char broadcast_mac[6];
    int i;

    for(i=0; i < 6; i++)
    {
        broadcast_mac[i] = 0xff;
    }

    temp_hwa_info = hwa_info_list_head;

    while(temp_hwa_info != NULL)
    {
        /* Do not broadcast over interface eth0 and lo and interface with alias IP address */
        if(!( (strcmp(temp_hwa_info->if_name, "eth0") == 0) || (strcmp(temp_hwa_info->if_name, "lo") == 0) ||
              (temp_hwa_info->ip_alias == 1)                || (temp_hwa_info->if_index == excluded_if_index) ))
        {
            temp_eth_frame = prepare_ethernet_frame(broadcast_mac, (unsigned char*)temp_hwa_info->if_haddr, (union ethernet_payload)rreq);
            send_ethernet_frame(pf_sock_fd, broadcast_mac, temp_hwa_info, temp_eth_frame, PACKET_BROADCAST);
        }
        temp_hwa_info = temp_hwa_info->hwa_next;
    }
}
/*******************************end of broadcast_odr_rreq function*************************/



/*******************************start of prepare_ethernet_frame function*************************/
struct ethernet_frame* prepare_ethernet_frame(unsigned char* dest_mac, unsigned char* source_mac, union ethernet_payload payload)
{
    struct ethernet_frame* temp_eth_frame;
    int i;
    temp_eth_frame = (struct ethernet_frame*)malloc(sizeof(struct ethernet_frame));

    /* prepare ethernet header */
    //for(i = 0; i < 6; i++)
    //{
    //    temp_eth_frame->header.dest_mac[i] = dest_mac[i];
    //    temp_eth_frame->header.source_mac[i] = source_mac[i];
    //}
    memcpy(temp_eth_frame->header.dest_mac, dest_mac, sizeof(temp_eth_frame->header.dest_mac));
    memcpy(temp_eth_frame->header.source_mac, source_mac, sizeof(temp_eth_frame->header.source_mac));
    temp_eth_frame->header.protocal = htons(ODR_PROTOCOL_ID);

    /* prepare ethernet payload */
    memcpy(&temp_eth_frame->payload, &payload, sizeof(union ethernet_payload));

    return temp_eth_frame;
}
/*******************************end of prepare_ethernet_frame function*************************/

/*******************************start of update_rcvd_rreq_list function*************************/
void update_rcvd_rreq_list(struct ethernet_frame* rreq)
{
    struct rcvd_odr_rrequest_list *temp_rcvd_rreq = rcvd_rreq_list_head;
    struct rcvd_odr_rrequest_list *prev_temp_rcvd_rreq = NULL;

    while(temp_rcvd_rreq != NULL)
    {
        if(strcmp(rreq->payload.rreq.originator_canonical_ip, temp_rcvd_rreq->rcvd_rreq->payload.rreq.originator_canonical_ip) == 0)
        {
            break;
        }
        prev_temp_rcvd_rreq = temp_rcvd_rreq;
        temp_rcvd_rreq = temp_rcvd_rreq->next_rcvd_rreq;
    }

    if(temp_rcvd_rreq == NULL)
    {
        temp_rcvd_rreq = (struct rcvd_odr_rrequest_list*)malloc(sizeof(struct rcvd_odr_rrequest_list));

        temp_rcvd_rreq->rcvd_rreq = (struct ethernet_frame*)malloc(sizeof(struct ethernet_frame));
        memcpy(temp_rcvd_rreq->rcvd_rreq, rreq, sizeof(struct ethernet_frame));
        temp_rcvd_rreq->next_rcvd_rreq = NULL;

        if(prev_temp_rcvd_rreq != NULL)
        {
           prev_temp_rcvd_rreq->next_rcvd_rreq = temp_rcvd_rreq;
        }
        else /* if previous rreq is NULL => rcvd rreq list is empty */
        {
            rcvd_rreq_list_head = temp_rcvd_rreq;
        }
    }
    else
    {
        free(temp_rcvd_rreq->rcvd_rreq);
        temp_rcvd_rreq->rcvd_rreq = (struct ethernet_frame*)malloc(sizeof(struct ethernet_frame));
        memcpy(temp_rcvd_rreq->rcvd_rreq, rreq, sizeof(struct ethernet_frame));
    }
}
/*******************************end of update_rcvd_rreq_list function*************************/

/*******************************start of get_hwa_info function*************************/
struct hwa_info* get_hwa_info(int if_index)
{
    struct hwa_info* temp_hwa_info = hwa_info_list_head;

    while(temp_hwa_info != NULL)
    {
        if(temp_hwa_info->if_index == if_index)
            break;
        temp_hwa_info = temp_hwa_info->hwa_next;
    }
    return temp_hwa_info;

}
/*******************************end of get_hwa_info function*************************/

/*******************************start of send_ethernet_frame function*************************/
void send_ethernet_frame(int pf_sock_fd, unsigned char* dest_mac, struct hwa_info* hw_if, struct ethernet_frame* eth_frame, uint16_t packet_type)
{
    struct sockaddr_ll dest_sock_addr;
    int i,j;
    char odr_host_name[128], source_host_name[128], dest_host_name[128];
    struct in_addr src_in_addr, dest_in_addr;
    struct hostent *h_temp;
    char *prnt_src_mac, *prnt_dest_mac;


    /* prepare socket address  */
    memset(&dest_sock_addr, 0, sizeof(struct sockaddr_ll));

    dest_sock_addr.sll_family = PF_PACKET;
    dest_sock_addr.sll_hatype = ARPHRD_ETHER;
    dest_sock_addr.sll_pkttype = packet_type; /* contained in if_packet.h */
    dest_sock_addr.sll_halen = ETH_ALEN; /* contained in if_ether.h */
    dest_sock_addr.sll_ifindex = hw_if->if_index;
    dest_sock_addr.sll_protocol = ODR_PROTOCOL_ID;

    if(packet_type == PACKET_BROADCAST)
    {
        for(i = 0; i < 6; i++)
        {
            dest_sock_addr.sll_addr[i] = 0xff;
        }
    }
    else if(packet_type == PACKET_OTHERHOST)
    {
        for(i = 0; i < 6; i++)
        {
            dest_sock_addr.sll_addr[i] = dest_mac[i];
        }
    }
    /* Unused octate */
    dest_sock_addr.sll_addr[6] = 0x00;
    dest_sock_addr.sll_addr[7] = 0x00;
    /* message */

    if( sendto(pf_sock_fd, eth_frame, sizeof(struct ethernet_frame), 0, (struct sockaddr*)&dest_sock_addr, sizeof(struct sockaddr_ll)) < 0 )
    {
        if(packet_type == PACKET_BROADCAST)
            fprintf(stderr, "Error while broadcasting RREQ on interface - %s: %s\n", hw_if->if_name, strerror(errno));
        else if(packet_type == PACKET_OTHERHOST)
            fprintf(stderr, "Error while sending ODR message on interface - %s: %s\n", hw_if->if_name, strerror(errno));

        unlink(ODR_SUN_PATH);
        exit(1);
    }
    /* print out message regarding successful send */
    memset(odr_host_name, 0, sizeof(odr_host_name));
    memset(source_host_name, 0, sizeof(source_host_name));
    memset(dest_host_name, 0, sizeof(dest_host_name));
    memset(&src_in_addr, 0, sizeof(struct in_addr));
    memset(&dest_in_addr, 0, sizeof(struct in_addr));

    if(gethostname(odr_host_name, sizeof(odr_host_name)) < 0)
    {
        fprintf(stderr, "Error while retrieving ODR host name: %s", strerror(errno));
        unlink(ODR_SUN_PATH);
        exit(1);
    }

    if(inet_pton(AF_INET, eth_frame->payload.info.source_canonical_ip, &src_in_addr) < 0)
    {
        fprintf(stderr, "Error while obtaining IP address in network format: %s\n", strerror(errno));
        unlink(ODR_SUN_PATH);
        exit(1);
    }

    if(inet_pton(AF_INET, eth_frame->payload.info.dest_canonical_ip, &dest_in_addr) < 0)
    {
        fprintf(stderr, "Error while obtaining IP address in network format: %s\n", strerror(errno));
        unlink(ODR_SUN_PATH);
        exit(1);
    }

    h_temp = gethostbyaddr(&src_in_addr, 4, AF_INET);
    strcpy(source_host_name, h_temp->h_name);

    h_temp = gethostbyaddr(&dest_in_addr, 4, AF_INET);
    strcpy(dest_host_name, h_temp->h_name);

    prnt_src_mac = malloc(19);
    prnt_dest_mac = malloc(19);
    memset(prnt_src_mac, 0, 19);
    memset(prnt_dest_mac, 0, 19);

     for(i = 0, j = 0; i < 6; i++, j = j+3)
    {
        sprintf((char*)(prnt_src_mac + j), (i != 5)? "%02x:" : "%02x" , hw_if->if_haddr[i] & 0xff);
        sprintf((char*)(prnt_dest_mac + j), (i != 5)? "%02x:" : "%02x", dest_mac[i] & 0xff);
    }


    fprintf(stdout, "ODR at node %s: sending frame hdr src %s dest %s\n",
                            odr_host_name, prnt_src_mac, prnt_dest_mac);
    fprintf(stdout, "                        ODR msg type %d src %s dest %s\n",
                        ntohs(eth_frame->payload.info.odr_msg_type), source_host_name, dest_host_name);

}
/*******************************end of send_ethernet_frame function*************************/

/*******************************start of  process_rcvd_ethernet_frame function*************************/
void process_rcvd_ethernet_frame(int pf_sock_fd, int domain_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame)
{

    /* process ethernet frame according to ODR message type */
    switch(ntohs(rcvd_eth_frame.payload.info.odr_msg_type))
    {
        case ODR_RREQUEST:
            /* message */
            fprintf(stdout, "Received RREQ\n");
            process_rcvd_odr_rreq(pf_sock_fd, remote_sock_addr, rcvd_eth_frame);
            break;
        case ODR_RREPLY:
            /* message */
            fprintf(stdout, "Received RREP\n");
            process_rcvd_odr_rrep(pf_sock_fd, remote_sock_addr, rcvd_eth_frame);
            break;
        case ODR_APP_PAYLOAD:
            /* message */
            fprintf(stdout, "Received PAYLOAD\n");
            process_rcvd_odr_app_payload(pf_sock_fd, domain_sock_fd, remote_sock_addr, rcvd_eth_frame);
            break;
        default:
            fprintf(stdout, "Unknown ODR message type: message can't be processed\n");
            return;
    }
}
/*******************************end of  process_rcvd_ethernet_frame function*************************/


/*******************************start of  process_rcvd_odr_rreq function*************************/
void process_rcvd_odr_rreq(int pf_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame)
{
    struct ethernet_frame *prev_rcvd_rreq = NULL;
    struct routing_table_entry *temp_route_tab_entry_src, *temp_route_tab_entry_dest ;
    uint16_t is_host_destination = 0;
    uint16_t rrep_sent_already = 0;
    struct odr_rreply* new_odr_rrep;
    struct hwa_info *temp_hwa_info;
    struct ethernet_frame *temp_eth_frame;
    struct odr_rrequest *temp_odr_rreq;
    /**************** check if received ODR request should be processed further *******************/
    /* rreq was sent by host itself, no need to process */
    if(strcmp(rcvd_eth_frame.payload.rreq.originator_canonical_ip, host_canonical_ip) == 0)
        return;

    prev_rcvd_rreq = get_rcvd_rreqs(rcvd_eth_frame.payload.rreq.originator_canonical_ip);

    if(prev_rcvd_rreq != NULL)
    {
        /* rreq has lower broadcast ID then already present rcvd rreq from the originator; ignore */
        if( ntohl(rcvd_eth_frame.payload.rreq.broadcast_id) < ntohl(prev_rcvd_rreq->payload.rreq.broadcast_id) )
            return;
        /* if broadcast ID are same */
        else if(ntohl(rcvd_eth_frame.payload.rreq.broadcast_id) == ntohl(prev_rcvd_rreq->payload.rreq.broadcast_id))
        {
            /* if message arrives from the same neighbor with same hop count OR has higher hop count; ignore */
            if( (ntohl(rcvd_eth_frame.payload.rreq.hop_count) > ntohl(prev_rcvd_rreq->payload.rreq.hop_count))
                ||
                (
                  (strncmp(rcvd_eth_frame.header.source_mac, prev_rcvd_rreq->header.source_mac, 6) == 0)
                  &&
                  (ntohl(rcvd_eth_frame.payload.rreq.hop_count) == ntohl(prev_rcvd_rreq->payload.rreq.hop_count))
                )
              )
                return;
        }
    }

    /* update received rreq in the rcvd_rreq_list */
    update_rcvd_rreq_list(&rcvd_eth_frame);

    /********************************* process the routing table *******************************/
    if(strcmp(rcvd_eth_frame.payload.info.dest_canonical_ip, host_canonical_ip) == 0)
        is_host_destination = 1;

    /* remove stale routing table entries */
    remove_stale_routing_tab_entry();

    /* update the routing table entry corresponding to the originator of rreq ethernet frame */
    temp_route_tab_entry_src = (struct routing_table_entry*)malloc(sizeof(struct routing_table_entry));

    /* prepare new routing table entry */
    strcpy(temp_route_tab_entry_src->dest_canonical_ip, rcvd_eth_frame.payload.info.source_canonical_ip);
    gettimeofday(&temp_route_tab_entry_src->entry_time, NULL);
    temp_route_tab_entry_src->hop_count = ntohl(rcvd_eth_frame.payload.rreq.hop_count);
    temp_route_tab_entry_src->next_entry = NULL;
    temp_route_tab_entry_src->if_index = remote_sock_addr.sll_ifindex;
    memcpy(temp_route_tab_entry_src->neighbour_mac, rcvd_eth_frame.header.source_mac, 6);

    update_routing_table_entry(*temp_route_tab_entry_src);

    /* if force_route_discovery flag is set, delete routing entry corresponding to destination */
    if( (ntohs(rcvd_eth_frame.payload.rreq.force_route_discovery) == 1) && is_host_destination == 0 )
    {
        remove_routing_table_entry(rcvd_eth_frame.payload.info.dest_canonical_ip);
    }

    /************************************** genereate RREP if required **********************************/
    if(ntohs(rcvd_eth_frame.payload.rreq.rrep_already_sent) == 0)
    {
        temp_route_tab_entry_dest = NULL;
        /* if host is not destination, check if it has route to destination available */
        if(is_host_destination == 0)
        {
            temp_route_tab_entry_dest = get_routing_table_entry(rcvd_eth_frame.payload.info.dest_canonical_ip);
        }
        /* if host has route to destination or host itself is destination; send RREP to originator */
        if((temp_route_tab_entry_dest != NULL) || (is_host_destination == 1))
        {
            /* prepare ODR reply to the originator of rreq */
            new_odr_rrep = (struct odr_rreply*)malloc(sizeof(struct odr_rreply));

            strcpy(new_odr_rrep->dest_canonical_ip, rcvd_eth_frame.payload.info.dest_canonical_ip);
            strcpy(new_odr_rrep->originator_canonical_ip, rcvd_eth_frame.payload.info.source_canonical_ip);
            new_odr_rrep->force_discovery = rcvd_eth_frame.payload.rreq.force_route_discovery;
            new_odr_rrep->odr_msg_type =  htons(1);

            if(temp_route_tab_entry_dest != NULL)
                new_odr_rrep->hop_count =  htonl(temp_route_tab_entry_dest->hop_count + 1);
            else
                new_odr_rrep->hop_count = 1;

            /* prepare ethernet frame */
            temp_hwa_info = get_hwa_info(temp_route_tab_entry_src->if_index);

            temp_eth_frame = prepare_ethernet_frame((unsigned char*)(temp_route_tab_entry_src->neighbour_mac), (unsigned char*)temp_hwa_info->if_haddr, (union ethernet_payload)(*new_odr_rrep));

            /* send ethernet frame containing RREP to the originator of rreq */
            send_ethernet_frame(pf_sock_fd, (unsigned char*)(temp_route_tab_entry_src->neighbour_mac), temp_hwa_info, temp_eth_frame, PACKET_OTHERHOST);
            rrep_sent_already = 1;
        }
    }

    /************************************* Broadcast RREQ***************************************/
    if(is_host_destination == 0)
    {
        temp_odr_rreq = (struct odr_rrequest*)malloc(sizeof(struct odr_rrequest));
        memcpy(temp_odr_rreq, &rcvd_eth_frame.payload.rreq, sizeof(struct odr_rrequest));

        temp_odr_rreq->hop_count = htonl( ntohl(temp_odr_rreq->hop_count) +  1);
        if( ntohs(temp_odr_rreq->rrep_already_sent) == 0)
            temp_odr_rreq->rrep_already_sent = htons(rrep_sent_already);

        broadcast_odr_rreq(pf_sock_fd, *temp_odr_rreq, remote_sock_addr.sll_ifindex);
    }
}
/*******************************end of  process_rcvd_odr_rreq function*************************/

/*******************************start of  get_rcvd_rreqs function*************************/
struct ethernet_frame* get_rcvd_rreqs(char* originator_canonical_ip_ptr)
{
    struct rcvd_odr_rrequest_list *temp_rcvd_rreq = rcvd_rreq_list_head;
    while(temp_rcvd_rreq != NULL)
    {
        if(strcmp(originator_canonical_ip_ptr, temp_rcvd_rreq->rcvd_rreq->payload.rreq.originator_canonical_ip) == 0)
        {
            break;
        }
        temp_rcvd_rreq = temp_rcvd_rreq->next_rcvd_rreq;
    }

    return (temp_rcvd_rreq == NULL)? NULL : temp_rcvd_rreq->rcvd_rreq;
}
/*******************************end of  get_rcvd_rreqs function*************************/

/*******************************start of  update_routing_table_entry function*************************/
void update_routing_table_entry(struct routing_table_entry new_route_tab_entry)
{
    struct routing_table_entry *temp_route_tab_entry = head_routing_tab_entry;
    struct routing_table_entry *prev_route_tab_entry = NULL;
    struct routing_table_entry *new_route_tab_entry_copy = (struct routing_table_entry*)malloc(sizeof(struct routing_table_entry)) ;

    memcpy(new_route_tab_entry_copy, &new_route_tab_entry, sizeof(struct routing_table_entry));
    /*message */
    fprintf(stdout, "Updating routing entry for destination:%s\n", new_route_tab_entry.dest_canonical_ip);
    while(temp_route_tab_entry != NULL)
    {
        if(strcmp(temp_route_tab_entry->dest_canonical_ip, new_route_tab_entry.dest_canonical_ip) == 0)
            break;
        prev_route_tab_entry = temp_route_tab_entry;
        temp_route_tab_entry = temp_route_tab_entry->next_entry;
    }

    if(temp_route_tab_entry == NULL)
    {
        if(prev_route_tab_entry != NULL)
        {
            prev_route_tab_entry->next_entry = new_route_tab_entry_copy;
        }
        else /* routing table is empty */
        {
            head_routing_tab_entry = new_route_tab_entry_copy;
        }
    }
    else
    {
        temp_route_tab_entry->entry_time = new_route_tab_entry.entry_time;
        temp_route_tab_entry->hop_count = new_route_tab_entry.hop_count;
        memcpy(temp_route_tab_entry->neighbour_mac, new_route_tab_entry.neighbour_mac, 6);
        temp_route_tab_entry->if_index = new_route_tab_entry.if_index;
    }
}
/*******************************end of update_routing_table_entry function*************************/

/*******************************start of remove_stale_routing_tab_entry function*************************/
void remove_stale_routing_tab_entry()
{
    struct routing_table_entry *temp_route_tab_entry = head_routing_tab_entry;
    struct routing_table_entry  *prev_route_tab_enrty = NULL;
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    uint32_t time_difference;
    while(temp_route_tab_entry != NULL)
    {
        if(stale_time < (time_difference = (current_time.tv_sec + current_time.tv_usec/1000000) - (temp_route_tab_entry->entry_time.tv_sec + temp_route_tab_entry->entry_time.tv_usec/1000000) ))
        {
            /* message */
            fprintf(stdout, "Time of existance: %u > Staleness Time: %u\n", time_difference, stale_time);
            fprintf(stdout, "Removing stale routing table entry for destination :%s\n", temp_route_tab_entry->dest_canonical_ip);
            if(prev_route_tab_enrty != NULL)
            {
                prev_route_tab_enrty->next_entry = temp_route_tab_entry->next_entry;
                free(temp_route_tab_entry);
                temp_route_tab_entry = prev_route_tab_enrty->next_entry;
            }
            else /* there is only one entry or entry is head, which will be deleted */
            {
                head_routing_tab_entry = temp_route_tab_entry->next_entry;
                free(temp_route_tab_entry);
                temp_route_tab_entry = head_routing_tab_entry;
            }
            continue;
        }

        prev_route_tab_enrty = temp_route_tab_entry;
        temp_route_tab_entry = temp_route_tab_entry->next_entry;

    }

}
/*******************************end of remove_stale_routing_tab_entry function*************************/

/*******************************start of update_rcvd_rrep_list function*************************/
void update_rcvd_rrep_list(struct ethernet_frame* rrep)
{
    struct rcvd_odr_rrep_list* temp_rcvd_rrep = rcvd_rrep_list_head;
    struct rcvd_odr_rrep_list* prev_rcvd_rrep = NULL;
    struct ethernet_frame* temp_rrep = (struct ethernet_frame*)malloc(sizeof(struct ethernet_frame));

    memcpy(temp_rrep, rrep, sizeof(struct ethernet_frame));

    while(temp_rcvd_rrep != NULL)
    {
        if( (strcmp(temp_rcvd_rrep->rcvd_rrep->payload.info.source_canonical_ip, rrep->payload.info.source_canonical_ip) == 0)
            &&
            (strcmp(temp_rcvd_rrep->rcvd_rrep->payload.info.dest_canonical_ip, rrep->payload.info.dest_canonical_ip) == 0)
          )
        {
            break;
        }
        prev_rcvd_rrep = temp_rcvd_rrep;
        temp_rcvd_rrep = temp_rcvd_rrep->next_rcvd_rrep;
    }

    if(temp_rcvd_rrep == NULL)
    {
        temp_rcvd_rrep = (struct rcvd_odr_rrep_list*)malloc(sizeof(struct rcvd_odr_rrep_list));
        temp_rcvd_rrep->next_rcvd_rrep = NULL;
        temp_rcvd_rrep->rcvd_rrep = temp_rrep;
        if(prev_rcvd_rrep != NULL)
        {
            prev_rcvd_rrep->next_rcvd_rrep = temp_rcvd_rrep;
        }
        else /* no rcvd rrep in the list*/
        {
            rcvd_rrep_list_head = temp_rcvd_rrep;
        }
    }
    else
    {
        free(temp_rcvd_rrep->rcvd_rrep);
        temp_rcvd_rrep->rcvd_rrep = temp_rrep;
    }

}
/*******************************end of update_rcvd_rrep_list function*************************/

/*******************************start of process_rcvd_odr_rrep function*************************/
void process_rcvd_odr_rrep(int pf_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame)
{
    uint16_t is_host_originator = 0;
    struct ethernet_frame *prev_rcvd_rrep;
    struct routing_table_entry *temp_route_tab_entry_dest;
    struct routing_table_entry *temp_route_tab_entry_source;
    struct odr_rrequest *temp_rreq;
    struct hwa_info* hw_if;
    struct ethernet_frame* temp_eth_frame;
    union ethernet_payload* relay_payload;

    /****************************** update rcvd rrep, if required *******************************/
    /* if originator of RREP itself, receives RREP again(not possible, safety); ignore */
    if(strcmp(rcvd_eth_frame.payload.info.dest_canonical_ip , host_canonical_ip) == 0)
        return;

    /* if force_route_discovery flag is not set, check if RREP can be discarded */
    if(ntohs(rcvd_eth_frame.payload.rreq.force_route_discovery) != 1)
    {
        prev_rcvd_rrep = get_rcvd_rreps(rcvd_eth_frame.payload.info.source_canonical_ip, rcvd_eth_frame.payload.info.dest_canonical_ip);

        if(prev_rcvd_rrep != NULL)
        {
            /* if previously rcvd rrep hop count is less; ignore currently received rrep */
            if( (ntohl(prev_rcvd_rrep->payload.rrep.hop_count) < ntohl(rcvd_eth_frame.payload.rrep.hop_count))
                ||
                ( (ntohl(prev_rcvd_rrep->payload.rrep.hop_count) == ntohl(rcvd_eth_frame.payload.rrep.hop_count))
                   &&
                  (strncmp(prev_rcvd_rrep->header.source_mac, rcvd_eth_frame.header.source_mac, 6) == 0)
                )
              )
            {
                return;
            }
        }
    }

    /* update already rcvd rrep */
    update_rcvd_rrep_list(&rcvd_eth_frame);

    /********************************* process routing table **********************/
    /* remove stale entries from routing table */
    remove_stale_routing_tab_entry();

    /* Update routing table entry corresponding to destination in RREP */
    temp_route_tab_entry_dest = (struct routing_table_entry*)malloc(sizeof(struct routing_table_entry));

    /* prepare routing table entry */
    strcpy(temp_route_tab_entry_dest->dest_canonical_ip, rcvd_eth_frame.payload.info.dest_canonical_ip);
    gettimeofday(&temp_route_tab_entry_dest->entry_time, NULL);
    temp_route_tab_entry_dest->hop_count = ntohl(rcvd_eth_frame.payload.rrep.hop_count);
    temp_route_tab_entry_dest->if_index = remote_sock_addr.sll_ifindex;
    temp_route_tab_entry_dest->next_entry = NULL;
    memcpy(temp_route_tab_entry_dest->neighbour_mac, rcvd_eth_frame.header.source_mac, 6);

    /* update routing table entry*/
    update_routing_table_entry(*temp_route_tab_entry_dest);

    /************************************** send RREP, if required **********************************/

    /* check if host is orginator of corresponding RREQ */
    if(strcmp(rcvd_eth_frame.payload.info.source_canonical_ip, host_canonical_ip) == 0)
        is_host_originator = 1;

    if(is_host_originator == 1)
    {
        /* process pending rreps */
        process_pending_rreps(pf_sock_fd, temp_route_tab_entry_dest);

        /* process pending app_payloads */
        process_pending_app_payloads(pf_sock_fd, temp_route_tab_entry_dest);
    }
    else /* intermediate node; relay received RREP */
    {
        /* get routing table entry for the originator of corresponding RREQ */
        temp_route_tab_entry_source = get_routing_table_entry(rcvd_eth_frame.payload.info.source_canonical_ip);

        /* update the hop count in RREP */

        //relay_payload = (union ethernet_payload*)malloc(sizeof(union ethernet_payload));
        //memcpy(relay_payload, &rcvd_eth_frame.payload, sizeof(union ethernet_payload));

        //relay_payload->app_payload.hop_count = htonl( ntohl(relay_payload->app_payload.hop_count) + 1);
        rcvd_eth_frame.payload.rrep.hop_count = htonl( ntohl(rcvd_eth_frame.payload.rrep.hop_count) + 1);

        /* if route is not present, perform discovery again; send RREQ */
        if(temp_route_tab_entry_source == NULL)
        {
            /* prepare new RREQ */
            temp_rreq = prepare_odrrequest(rcvd_eth_frame.payload.info.source_canonical_ip, 0, 0);

            /* broadcast RREQ */
            broadcast_odr_rreq(pf_sock_fd, *temp_rreq, -1);

            /* add RREP to pending RREP list */
            add_rrep_to_pending_list(&rcvd_eth_frame.payload.rrep);
        }
        else /* route exists, send directly */
        {
            hw_if = get_hwa_info(temp_route_tab_entry_source->if_index);

            /*prepare ethernet frame */
            temp_eth_frame = prepare_ethernet_frame(temp_route_tab_entry_source->neighbour_mac, (unsigned char*)hw_if->if_haddr, (union ethernet_payload)rcvd_eth_frame.payload);

            /* send ethernet frame containing RREP */
            send_ethernet_frame(pf_sock_fd, temp_route_tab_entry_source->neighbour_mac, hw_if, temp_eth_frame, PACKET_OTHERHOST);
        }
    }
}
/*******************************end of process_rcvd_odr_rrep function*************************/


/*******************************start of get_rcvd_rreps function*************************/
struct ethernet_frame* get_rcvd_rreps(char* originator_canonical_ip_ptr, char* dest_canonical_ptr)
{
    struct rcvd_odr_rrep_list *temp_rrep = rcvd_rrep_list_head;

    while(temp_rrep != NULL)
    {
        if((strcmp(temp_rrep->rcvd_rrep->payload.info.dest_canonical_ip, dest_canonical_ptr) == 0) && (strcmp(temp_rrep->rcvd_rrep->payload.info.source_canonical_ip, originator_canonical_ip_ptr) == 0))
        {
            break;
        }
        temp_rrep = temp_rrep->next_rcvd_rrep;
    }
    return (temp_rrep  == NULL) ? NULL : temp_rrep->rcvd_rrep;
}
/*******************************end of get_rcvd_rreps function*************************/

/*******************************start of process_pending_rreps function*************************/
void process_pending_rreps(int pf_sock_fd, struct routing_table_entry *dest_route_entry)
{
    struct pending_odr_rrep_list *temp_pending_rrep = pending_rrep_list_head;
    struct pending_odr_rrep_list *prev_pending_rrep = NULL;
    struct hwa_info* temp_hw_if;
    struct ethernet_frame *temp_eth_frame;
    temp_hw_if = get_hwa_info(dest_route_entry->if_index);
    while(temp_pending_rrep != NULL)
    {
        if(strcmp(temp_pending_rrep->rrep->originator_canonical_ip, dest_route_entry->dest_canonical_ip) == 0)
        {
            /* prepare ethernet frame*/
            temp_eth_frame = prepare_ethernet_frame(dest_route_entry->neighbour_mac, (unsigned char*)temp_hw_if->if_haddr, (union ethernet_payload)(*temp_pending_rrep->rrep));

            /* send ethernet frame */
            send_ethernet_frame(pf_sock_fd, dest_route_entry->neighbour_mac, temp_hw_if, temp_eth_frame, PACKET_OTHERHOST);

            /* remove processed rrep from the pending list */
            if(prev_pending_rrep != NULL)
            {
                prev_pending_rrep->next_pending_rrep = temp_pending_rrep->next_pending_rrep;
                free(temp_pending_rrep);
                temp_pending_rrep = prev_pending_rrep->next_pending_rrep;
            }
            else /* removed entry was head or the only entry present */
            {
                pending_rrep_list_head = temp_pending_rrep->next_pending_rrep;
                free(temp_pending_rrep);
                temp_pending_rrep = pending_rrep_list_head;
            }
            continue;
        }
        prev_pending_rrep = temp_pending_rrep;
        temp_pending_rrep = temp_pending_rrep->next_pending_rrep;
    }
}
/*******************************end of process_pending_rreps function*************************/

/*******************************start of process_app_payloads function*************************/
void process_pending_app_payloads(int pf_sock_fd, struct routing_table_entry *dest_route_entry)
{
    struct pending_app_payload_list *temp_app_payload = pending_payload_list_head;
    struct pending_app_payload_list *prev_app_payload = NULL;
    struct hwa_info *temp_hw_if;
    struct ethernet_frame *temp_eth_frame;

    temp_hw_if = get_hwa_info(dest_route_entry->if_index);

    while(temp_app_payload != NULL)
    {
        if(strcmp(temp_app_payload->payload->dest_canonical_ip, dest_route_entry->dest_canonical_ip) == 0)
        {
            /* prepare ethernet frame*/
            temp_eth_frame = prepare_ethernet_frame(dest_route_entry->neighbour_mac, (unsigned char*)temp_hw_if->if_haddr, (union ethernet_payload)(*temp_app_payload->payload));

            /* send ethernet frame */
            send_ethernet_frame(pf_sock_fd, dest_route_entry->neighbour_mac, temp_hw_if, temp_eth_frame, PACKET_OTHERHOST);

            /* remove processed app_payload from the pending list */
            if(prev_app_payload != NULL)
            {
                prev_app_payload->next_pending_payload = temp_app_payload->next_pending_payload;
                free(temp_app_payload);
                temp_app_payload = prev_app_payload->next_pending_payload;
            }
            else
            {
                pending_payload_list_head = temp_app_payload->next_pending_payload;
                free(temp_app_payload);
                temp_app_payload = pending_payload_list_head;
            }
            continue;
        }
        prev_app_payload = temp_app_payload;
        temp_app_payload = temp_app_payload->next_pending_payload;
    }
}
/*******************************end of process_app_payloads function*************************/

/*******************************start of add_rrep_to_pending_list function*************************/
void add_rrep_to_pending_list(struct odr_rreply *rrep)
{
    struct pending_odr_rrep_list *temp_pending_rrep;
    struct pending_odr_rrep_list *new_pending_rrep;

    new_pending_rrep = (struct pending_odr_rrep_list*)malloc(sizeof(struct pending_odr_rrep_list));
    new_pending_rrep->rrep = rrep;
    new_pending_rrep->next_pending_rrep = NULL;

    if(pending_rrep_list_head == NULL)
    {
        pending_rrep_list_head = new_pending_rrep;
    }
    else
    {
        temp_pending_rrep = pending_rrep_list_head;
        while(temp_pending_rrep->next_pending_rrep != NULL)
        {
            temp_pending_rrep = temp_pending_rrep->next_pending_rrep;
        }
        temp_pending_rrep->next_pending_rrep = new_pending_rrep;
    }
}
/******************************* end of add_rrep_to_pending_list function*************************/

/******************************* start of process_rcvd_odr_app_payload function*************************/
void process_rcvd_odr_app_payload(int pf_sock_fd, int domain_sock_fd, struct sockaddr_ll remote_sock_addr, struct ethernet_frame rcvd_eth_frame)
{
    struct routing_table_entry *temp_route_entry_source, *new_route_entry, *temp_route_entry_dest;
    uint16_t is_update_required = 0;
    uint16_t is_host_destination = 0;
    struct odr_rrequest *new_rreq;
    struct ethernet_frame *temp_eth_frame;
    struct hwa_info *hw_if;
    struct peer* temp_peer;
    struct sockaddr_un peer_sock_addr;
    struct peer_comm_data* temp_peer_comm_data;
    union ethernet_payload* relay_payload;

    /********************************* Use app_payload as free RREP to update path back to source***************************/
    /* remove stale routing entries*/
    remove_stale_routing_tab_entry();

    /*Get the routing entry for source of this app_payload */
    temp_route_entry_source = get_routing_table_entry(rcvd_eth_frame.payload.app_payload.source_canonical_ip);
    /* if routing entry is NULL, then use app payload to build an entry */
    /* if routing entry is not NULL, then check if app_payload offers lower hop count, if yes update existing entry */
    if(temp_route_entry_source != NULL)
    {
        if(temp_route_entry_source->hop_count > ntohl(rcvd_eth_frame.payload.app_payload.hop_count))
        {
            is_update_required = 1;
        }
    }

    if((temp_route_entry_source == NULL) || (is_update_required == 1))
    {
        /* prepare a new routing table entry */
        new_route_entry = (struct routing_table_entry*)malloc(sizeof(struct routing_table_entry));

        strcpy(new_route_entry->dest_canonical_ip, rcvd_eth_frame.payload.info.source_canonical_ip);
        gettimeofday(&new_route_entry->entry_time, NULL);
        new_route_entry->hop_count = ntohl(rcvd_eth_frame.payload.app_payload.hop_count);
        new_route_entry->if_index = remote_sock_addr.sll_ifindex;
        memcpy(new_route_entry->neighbour_mac, rcvd_eth_frame.header.source_mac, 6);
        new_route_entry->next_entry = NULL;

        /* update routing table with new entry */
        update_routing_table_entry(*new_route_entry);
    }

    /********************************* ODR app_payload processing ****************************/
    if(strcmp(rcvd_eth_frame.payload.info.dest_canonical_ip, host_canonical_ip) == 0)
    {
        is_host_destination = 1;
    }

    if(is_host_destination == 1) /* host is ultimate destination */
    {
        /* remove stale peers first */
        remove_stale_peers();

        /* get peer based on port no */
        temp_peer = get_peer(ntohs(rcvd_eth_frame.payload.app_payload.dest_port));

        if(temp_peer == NULL)
        {
            if(ntohs(rcvd_eth_frame.payload.app_payload.dest_port) == SERVER_PORT)
            {
                fprintf(stdout, "Server is not running on the host\n");
            }
            else
            {
                fprintf(stdout, "Intended client is not running on the host\n");
            }
            return;
        }

        /* prepare socket address to communicate with peer */
        memset(&peer_sock_addr, 0, sizeof(struct sockaddr_un));
        peer_sock_addr.sun_family = AF_UNIX;
        strcpy(peer_sock_addr.sun_path, temp_peer->sun_path);

        /* prepare peer communication data */
        temp_peer_comm_data = (struct peer_comm_data*)malloc(sizeof(struct peer_comm_data));
        memset(temp_peer_comm_data, 0, sizeof(struct peer_comm_data));
        strcpy(temp_peer_comm_data->canonical_ip, rcvd_eth_frame.payload.app_payload.source_canonical_ip);
        temp_peer_comm_data->port = ntohs(rcvd_eth_frame.payload.app_payload.source_port);
        strcpy(temp_peer_comm_data->msg, rcvd_eth_frame.payload.app_payload.msg);

        /* send data to peer */
        if(sendto(domain_sock_fd, temp_peer_comm_data, sizeof(struct peer_comm_data), 0, (struct sockaddr*)&peer_sock_addr, sizeof(struct sockaddr_un)) < 0)
        {
            fprintf(stderr, "Error while sending data to peer application process: %s\n", strerror(errno));
            return;
        }

    }
    else /* host is an intermediate node, relay the app_payload*/
    {
        /* get routing table entry for ultimate destination */
        temp_route_entry_dest = get_routing_table_entry(rcvd_eth_frame.payload.info.dest_canonical_ip);

        /* update hop count */
        rcvd_eth_frame.payload.app_payload.hop_count = htonl(ntohl(rcvd_eth_frame.payload.app_payload.hop_count) + 1);

       // relay_payload = (union ethernet_payload*)malloc(sizeof(union ethernet_payload));
        //memcpy(relay_payload, &rcvd_eth_frame.payload, sizeof(union ethernet_payload));
        //relay_payload->app_payload.hop_count = htonl( ntohl(relay_payload->app_payload.hop_count) + 1);

        if(temp_route_entry_dest == NULL) /* Route to destination doesn't exist; broadcast RREQ */
        {
            /* prepare RREQ */
            new_rreq = prepare_odrrequest(rcvd_eth_frame.payload.info.dest_canonical_ip, 0, 0);

            /* broadcast RREQ */
            broadcast_odr_rreq(pf_sock_fd, *new_rreq, 0);

            /* add app_payload to pending list, to relay it later */
            add_payload_to_pending_list(&rcvd_eth_frame.payload.app_payload);
        }
        else
        {
            hw_if = get_hwa_info(temp_route_entry_dest->if_index);
            /* prepare ethernet frame */
            temp_eth_frame = prepare_ethernet_frame(temp_route_entry_dest->neighbour_mac, (unsigned char*)hw_if->if_haddr, (union ethernet_payload)rcvd_eth_frame.payload);
            /*send ethernet frame */
            send_ethernet_frame(pf_sock_fd, temp_route_entry_dest->neighbour_mac, hw_if, temp_eth_frame, PACKET_OTHERHOST);
        }
    }
}
/******************************* end of process_rcvd_odr_app_payload function*************************/


struct peer* get_peer(uint16_t port)
{
    struct peer *temp_peer = peer_list_head;

    while(temp_peer != NULL)
    {
        if(temp_peer->port == port)
        {
            break;
        }
        temp_peer = temp_peer->next_peer;
    }
    return temp_peer;
}

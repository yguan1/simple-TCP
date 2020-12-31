/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>

/*
 * These helper functions are exclusively used in this module, and are unlikely
 * called elsewhere, so we decided not to put them in the header file, which
 * is designed to be used by other modules
 */

typedef struct worker_args {
    serverinfo_t *si;
    chisocketentry_t *entry;
} worker_args_t;

/*
 * select_ISS - generate a random number ending in 00000 as ISS.
 *
 * Returns: ISS.
 */
int select_ISS();

/*
 * handle_PACKET_ARRIVAL - handle the event PACKET_ARRIVAL.
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int handle_PACKET_ARRIVAL(serverinfo_t *si, chisocketentry_t *entry);

/*
 * handle_RECEIVE - handle the event RECEIVE.
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int handle_RECEIVE(serverinfo_t *si, chisocketentry_t *entry);

/*
 * test_acceptability - test if a packet is acceptable.
 *
 * tcp_data: Pointer to tcp_data struct
 *
 * packet: Pointer to the packet being tested
 *
 * Returns: 1 if acceptable; 0 if not
 */
int test_acceptability(tcp_data_t *tcp_data, tcp_packet_t *packet);

/*
 * send_data_in_buffer - send the data in the send buffer if possible.
 * It also checks and handles the pending FIN, once the contents in the buffer
 * are all sent out.
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int send_data_in_buffer(serverinfo_t *si, chisocketentry_t *entry);

/*
 * send_FIN - send FIN.
 * Different from other send_* functions, this will also automatically
 * increment SND_NXT by 1
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int send_FIN(serverinfo_t *si, chisocketentry_t *entry);

/*
 * send_ACK - send a simple ACK based on current TCB info.
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int send_ACK(serverinfo_t *si, chisocketentry_t *entry);

/*
 * send_SYN - send SYN depending on the current state.
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int send_SYN(serverinfo_t *si, chisocketentry_t *entry);

/*
 * queue_request_FIN - queue request FIN.
 * This happens when a FIN is to be sent. The function checks if the buffer is
 * empty: if it is, then send a FIN immediately; if not, record the request and
 * send FIN immediately after the buffer is all sent
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int queue_request_FIN(serverinfo_t *si, chisocketentry_t *entry);

////////////RTT ESTIMATION////////////////

/*
 * compute_RTO - compute RTT and update RTO in TCP_DATA
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int compute_RTO(chisocketentry_t *entry);

/*
 * timespec_cmp - compare function for sorting retrans_node
 *
 * a, b: pointer of the two retrans_node being compared
 *
 * Returns: -1 if a < b, 0 if a = b, 1 if a > b
 */
int timespec_cmp(retrans_node_t *a, retrans_node_t *b);

/*
 * timespec_to_uint - convert timespec to uint64
 *
 * tp: timespec being converted
 *
 * Returns: time in nanosecond in uint64_t
 */
uint64_t timespec_to_uint(struct timespec tp);

//////////////RETRANSMISSION////////////////

/*
 * handle_TIMEOUT_RTX - handle TIMEOUT_RTX event
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int handle_TIMEOUT_RTX(serverinfo_t *si, chisocketentry_t *entry);

/*
 * remove_acked_packets - remove the acknowledged packets from the retrans queue
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int remove_acked_packets(chisocketentry_t *entry);

/*
 * retrans_callback - callback function for retransmission timer
 *
 * mt: pointer to the multitimer
 * 
 * st: pointer to the singletimer that's timing out
 * 
 * data: void pointer to worker_args struct that stores si and entry
 *
 * Returns: None
 */
void retrans_callback(multi_timer_t *mt, single_timer_t *st, void *data);

/*
 * retransmit - remove the acknowledged packets from the retrans queue
 *
 * si: Pointer to the serverinfo struct
 * 
 * entry: Pointer to the chisocketentry struct
 * 
 * packet: Pointer to the packet being retransmit
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int retransmit(serverinfo_t *si, chisocketentry_t *entry, tcp_packet_t *packet);

///////////////PERSIST TIMER/////////////////

/*
 * send_probe - send probe segment when persist timer timeout
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int send_probe(serverinfo_t *si, chisocketentry_t *entry);

/*
 * handle_TIMEOUT_PST - handle TIMEOUT_PST event
 *
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int handle_TIMEOUT_PST(serverinfo_t *si, chisocketentry_t *entry);

/*
 * retrans_callback - callback function for persist timer
 *
 * mt: pointer to the multitimer
 * 
 * st: pointer to the singletimer that's timing out
 * 
 * data: void pointer to worker_args struct that stores si and entry
 *
 * Returns: None
 */
void persist_callback(multi_timer_t *mt, single_timer_t *st, void *data);

/*
 * check_zero_window - check if SND_WND = 0
 * 
 * si: Pointer to the serverinfo struct
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: None
 */
void check_zero_window(serverinfo_t *si, chisocketentry_t *entry);

///////////////OUT OF ORDER/////////////////

/*
 * remove_contiguous_packets - remove the contiguous packets from the ooo queue
 *
 * entry: Pointer to the chisocketentry struct
 *
 * Returns: CHITCP_OK if everything is ok; error code otherwise
 */
int remove_contiguous_packets(chisocketentry_t *entry);

/*
 * seq_cmp - compare function for sorting ooo_node
 *
 * a, b: pointer of the two ooo_node being compared
 *
 * Returns: negative if a < b, 0 if a = b, positive if a > b
 */
int seq_cmp(ooo_node_t *a, ooo_node_t *b);

void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
    tcp_data->RTO = INITIAL_RTO;
    tcp_data->mt = calloc(1, sizeof(multi_timer_t));
    mt_init(tcp_data->mt, 2);
    mt_set_timer_name(tcp_data->mt, RETRANSMISSION, "retans");
    mt_set_timer_name(tcp_data->mt, PERSIST, "persist");
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
    
    mt_free(tcp_data->mt);
}


int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
        /* active OPEN */
        int ISS = select_ISS();

        /* update TCB */
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->ISS = ISS;
        tcp_data->SND_UNA = ISS;
        tcp_data->SND_NXT = ISS + 1;
        tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);

        send_SYN(si, entry);

        circular_buffer_set_seq_initial(&tcp_data->send, ISS + 1);

        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_SEND)
    {
        send_data_in_buffer(si, entry);
    }
    else if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        handle_RECEIVE(si, entry);
    }
    else if (event == APPLICATION_CLOSE)
    {
        queue_request_FIN(si, entry);
        chilog(DEBUG, "closing field set, ready to enter FIN_WAIT_1");
        chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        handle_RECEIVE(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        handle_RECEIVE(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        queue_request_FIN(si, entry);
        chitcpd_update_tcp_state(si, entry, LAST_ACK);
    }
    else if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

int select_ISS()
{
    /* use current time in millisecond as seed for random number */
    struct timeval now;
    gettimeofday(&now, NULL);
    srand(now.tv_usec);
    /* choose ISS ending in ZEROS */
    int n = (rand() % ISS_RAND_MOD) * ISS_END_ZEROS;
    return n;
}

int handle_PACKET_ARRIVAL(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *rcvd_packet = NULL;
    worker_args_t *wa = calloc(1, sizeof(worker_args_t));
    wa->si = si;
    wa->entry = entry;
    
    rcvd_packet = tcp_data->pending_packets->packet;
    chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    tcphdr_t *rcvd_header = TCP_PACKET_HEADER(rcvd_packet);
    chilog(DEBUG, "Received packet...");
    chilog_tcp(DEBUG, rcvd_packet, LOG_INBOUND);

    /* handle the packet according to RFC */
    if (entry->tcp_state == CLOSED)
    {
        chilog(TRACE, "packet arrives when state is CLOSED. Discarded.");
        return CHITCP_OK;
    }
    else if (entry->tcp_state == LISTEN)
    {
        chilog(TRACE, "TCP state: LISTEN");
        /* first check for an RST */
        if (rcvd_header->rst)
        {
            chilog(TRACE, "RST packet received and dropped");
            return CHITCP_OK;
        }
        /* second check for an ACK */
        if (rcvd_header->ack)
        {
            chilog(TRACE, "ACK packet received and dropeed");
            return CHITCP_OK;
        }
        /* third check for a SYN */
        if (rcvd_header->syn)
        {
            chilog(TRACE, "SYN packet received and processing...");

            tcp_data->RCV_NXT = SEG_SEQ(rcvd_packet) + 1;
            tcp_data->IRS = SEG_SEQ(rcvd_packet);
            tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
            chilog(DEBUG, "RCV_WND set as %d", tcp_data->RCV_WND);
            tcp_data->ISS = select_ISS();

            send_SYN(si, entry);

            tcp_data->SND_NXT = tcp_data->ISS + 1;
            tcp_data->SND_UNA = tcp_data->ISS;
            /* init the sequence number in the buffer */
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
            circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS + 1);

            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            return CHITCP_OK;
        }
        chilog(TRACE, "packet without RST or SYN received and dropped");
        return CHITCP_OK;
    }
    else if (entry->tcp_state == SYN_SENT)
    {
        chilog(TRACE, "TCP state: SYN_SENT");
        /* first check the ACK bit */
        if (rcvd_header->ack)
        {
            if (SEG_ACK(rcvd_packet) <= tcp_data->ISS ||
                SEG_ACK(rcvd_packet) > tcp_data->SND_NXT)
            {
                chilog(TRACE, "unacceptable packet received and dropped");
                return CHITCP_OK;
            }
            chilog(TRACE, "acceptable packet received and processing...");
        }

        /* RST check and security check ignored */

        /* fourth check the SYN bit */
        if (rcvd_header->syn)
        {
            tcp_data->RCV_NXT = SEG_SEQ(rcvd_packet) + 1;
            tcp_data->IRS = SEG_SEQ(rcvd_packet);
            tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
            chilog(DEBUG, "RCV_WND set as %d", tcp_data->RCV_WND);
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
            if (rcvd_header->ack)
            {
                tcp_data->SND_UNA = SEG_ACK(rcvd_packet);
                /* update RTO */
                compute_RTO(entry);
                /* set the retransmission timer */
                if (mt_is_active(tcp_data->mt, 0))
                    mt_cancel_timer(tcp_data->mt, 0);
                mt_set_timer(tcp_data->mt, RETRANSMISSION, tcp_data->RTO, retrans_callback, (void*) wa);
                chilog(DEBUG, "timer reset - RTO: %lu", tcp_data->RTO);
                /* remove acknowledged packets from the queue */
                remove_acked_packets(entry);
            }
                
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                tcp_data->SND_WND = SEG_WND(rcvd_packet);
                send_ACK(si, entry);
                /* update the state to ESTABLISHED */
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                check_zero_window(si, entry);
                return CHITCP_OK;
            }
            else
            {
                /* update the state to SYN_RCVD */
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);

                send_ACK(si, entry);
                return CHITCP_OK;
            }
        }
    }
    else
    {
        /* corresponds to "otherwise" in p.69 of rfc793 */

        /* States that can get here include (using RFC terms):
            * SYN-RECEIVED ESTABLISHED FIN-WAIT-1 FIN-WAIT-2
            * CLOSE-WAIT CLOSING LAST-ACK TIME-WAIT
            */

        chilog(TRACE, "in packet_handle, state is \"otherwise\"");

        /* first check the sequence number */
        if (!test_acceptability(tcp_data, rcvd_packet))
        {
            /* special allowance for ACK to update UNA when wnd is 0 */
            if (tcp_data->RCV_WND == 0 &&
                tcp_data->SND_UNA <= SEG_ACK(rcvd_packet) &&
                SEG_ACK(rcvd_packet) <= tcp_data->SND_NXT)
            {
                tcp_data->SND_UNA = SEG_ACK(rcvd_packet);
                
                /* update RTO */
                compute_RTO(entry);
                /* set the retransmission timer */
                if (mt_is_active(tcp_data->mt, 0))
                    mt_cancel_timer(tcp_data->mt, 0);
                mt_set_timer(tcp_data->mt, RETRANSMISSION, tcp_data->RTO, retrans_callback, (void*) wa);
                chilog(DEBUG, "timer reset - RTO: %lu", tcp_data->RTO);
                /* remove acknowledged packets from the queue */
                remove_acked_packets(entry);
            }

            chilog(DEBUG, "unacceptable packet received, sending ACK...");
            send_ACK(si, entry);
            return CHITCP_OK;
        }

        /* check if the packet is out of order */
        if (SEG_SEQ(rcvd_packet) > tcp_data->RCV_NXT)
        {
            chilog(DEBUG, "packet with seq %d:%d added to the ooo queue", 
                SEG_SEQ(rcvd_packet), SEG_SEQ(rcvd_packet) + TCP_PAYLOAD_LEN(rcvd_packet));
            ooo_node_t *node = calloc(1, sizeof(ooo_node_t));
            node->packet = rcvd_packet;
            LL_APPEND(tcp_data->ooo_queue, node);
            LL_SORT(tcp_data->ooo_queue, seq_cmp);
            return CHITCP_OK;
        }
        /* check if there are any contiguous segments */
        else if (tcp_data->ooo_queue)
        {
            if (SEG_SEQ(rcvd_packet) + TCP_PAYLOAD_LEN(rcvd_packet) == SEG_SEQ(tcp_data->ooo_queue->packet))
                remove_contiguous_packets(entry);
        }
        

        /* RST check and security check ignored */
        /* SYN check (if in SYN_RCVD and was passive OPEN, return
            * to LISTEN) ignored */

        /* fifth check the ACK field */
        if (rcvd_header->ack)
        {
            if (entry->tcp_state == SYN_RCVD)
            {
                if (tcp_data->SND_UNA <= SEG_ACK(rcvd_packet) &&
                    SEG_ACK(rcvd_packet) <= tcp_data->SND_NXT)
                {
                    tcp_data->SND_UNA = SEG_ACK(rcvd_packet);
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                    tcp_data->SND_WND = SEG_WND(rcvd_packet);

                    /* update RTO */
                    compute_RTO(entry);
                    /* set the retransmission timer */
                    if (mt_is_active(tcp_data->mt, 0))
                        mt_cancel_timer(tcp_data->mt, 0);
                    mt_set_timer(tcp_data->mt, RETRANSMISSION, tcp_data->RTO, retrans_callback, (void*) wa);
                    chilog(DEBUG, "timer reset - RTO: %lu", tcp_data->RTO);
                    /* remove acknowledged packets from the queue */
                    remove_acked_packets(entry);

                    check_zero_window(si, entry);
                    return CHITCP_OK;
                }
            }
            if (entry->tcp_state == ESTABLISHED ||
                entry->tcp_state == FIN_WAIT_1 ||
                entry->tcp_state == FIN_WAIT_2 ||
                entry->tcp_state == CLOSE_WAIT ||
                entry->tcp_state == CLOSING)
            {
                if (tcp_data->SND_UNA < SEG_ACK(rcvd_packet) &&
                    SEG_ACK(rcvd_packet) <= tcp_data->SND_NXT)
                {

                    tcp_data->SND_UNA = SEG_ACK(rcvd_packet);
                    tcp_data->SND_WND = SEG_WND(rcvd_packet);

                    /* update RTO */
                    compute_RTO(entry);
                    /* set the retransmission timer */
                    if (mt_is_active(tcp_data->mt, 0))
                        mt_cancel_timer(tcp_data->mt, 0);
                    mt_set_timer(tcp_data->mt, RETRANSMISSION, tcp_data->RTO, retrans_callback, (void*) wa);
                    chilog(DEBUG, "timer reset - RTO: %lu", tcp_data->RTO);
                    /* remove acknowledged packets from the queue */
                    remove_acked_packets(entry);

                    check_zero_window(si, entry);
                    if (!(entry->tcp_state == CLOSING || 
                            entry->tcp_state == FIN_WAIT_2))
                        send_data_in_buffer(si, entry);
                }
                if (tcp_data->SND_UNA >= SEG_ACK(rcvd_packet))
                {
                    chilog(TRACE, "duplicated ACK received and dropped");
                }
                if (SEG_ACK(rcvd_packet) > tcp_data->SND_NXT)
                {
                    send_ACK(si, entry);
                }
            }

            /* Note that some states are "In addition to the processing
                * for the ESTABLISHED state" so they appear twice */
            if (entry->tcp_state == FIN_WAIT_1)
            {
                /* check if our FIN is ACKed */
                if (tcp_data->SND_UNA == tcp_data->SND_NXT)
                {
                    chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
                }
            }
            if (entry->tcp_state == CLOSING)
            {
                if (SEG_ACK(rcvd_packet) == tcp_data->SND_NXT)
                {
                    /* note no TIME_WAIT this time */
                    chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                }
            }
            if (entry->tcp_state == LAST_ACK)
            {
                if (SEG_ACK(rcvd_packet) == tcp_data->SND_NXT)
                {
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                }
            }
            if (entry->tcp_state == TIME_WAIT)
            {
                /* note no TIME_WAIT this time */
                chitcpd_update_tcp_state(si, entry, CLOSED);
            }

        }

        /* seventh, process the segment text */
        if (TCP_PAYLOAD_LEN(rcvd_packet) && 
           (entry->tcp_state == ESTABLISHED ||
            entry->tcp_state == FIN_WAIT_1 ||
            entry->tcp_state == FIN_WAIT_2))
        {
            int len_writable = circular_buffer_available(&tcp_data->recv);
            int num_write = circular_buffer_write(
                &tcp_data->recv,
                TCP_PAYLOAD_START(rcvd_packet),
                MIN(len_writable, TCP_PAYLOAD_LEN(rcvd_packet)),
                0);
            tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
            tcp_data->RCV_NXT = circular_buffer_next(&tcp_data->recv);

            send_ACK(si, entry);
        }

        /* eighth, check the FIN bit */
        if (rcvd_header->fin)
        {
            if (entry->tcp_state == CLOSED ||
                entry->tcp_state == LISTEN ||
                entry->tcp_state == SYN_SENT)
            {
                return CHITCP_OK;
            }
            tcp_data->RCV_NXT = SEG_SEQ(rcvd_packet) + 1;

            tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *send_header;

            /* sending ACK for the FIN */
            send_ACK(si, entry);

            if (entry->tcp_state == SYN_RCVD ||
                entry->tcp_state == ESTABLISHED)
            {
                chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
            }
            if (entry->tcp_state == FIN_WAIT_1)
            {
                /* if it's been ACKed, it should have been processed
                    * in the last section and has already entered FIN_WAIT_2,
                    * so just move it to closing */
                chitcpd_update_tcp_state(si, entry, CLOSING);
            }
            if (entry->tcp_state == FIN_WAIT_2)
            {
                /* note no TIME_WAIT this time */
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                chitcpd_update_tcp_state(si, entry, CLOSED);
            }
            if (entry->tcp_state == CLOSE_WAIT ||
                entry->tcp_state == CLOSING ||
                entry->tcp_state == LAST_ACK)
            {
                /* Remain in this state and do nothing */
            }
            if (entry->tcp_state == TIME_WAIT)
            {
                /* Remain in this state and do nothing */
                /* Restart the timeout (not for this time) */
            }
        }
    }
    return CHITCP_OK;
}

int handle_TIMEOUT_RTX(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retrans_node_t *node;

    LL_FOREACH(tcp_data->retrans_queue, node)
    {
        chilog(DEBUG, "Retransmitting packet...");
        chilog_tcp(DEBUG, node->packet, LOG_OUTBOUND);
        chitcpd_send_tcp_packet(si, entry, node->packet);
    }

    /* update RTO */
    tcp_data->RTO = MAX(tcp_data->RTO / 2, MIN_RTO);
    /* set the retransmission timer */
    worker_args_t *wa = calloc(1, sizeof(worker_args_t));
    wa->si = si;
    wa->entry = entry;
    mt_set_timer(tcp_data->mt, RETRANSMISSION, tcp_data->RTO, retrans_callback, (void*) wa);
    return CHITCP_OK;
}

int send_probe(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    uint8_t *payload = calloc(1, sizeof(uint8_t));
    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    tcphdr_t *send_header;

    circular_buffer_peek(&tcp_data->send, payload, 1, false);
    chitcpd_tcp_packet_create(entry, send_packet, payload, 1);
    send_header = TCP_PACKET_HEADER(send_packet);
    send_header->seq = chitcp_htonl(tcp_data->SND_UNA);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);
    send_header->ack = 1;

    /* update SND.NXT */
    if (tcp_data->SND_UNA == tcp_data->SND_NXT) tcp_data->SND_NXT++;

    chilog(DEBUG, "Sending probe...");
    chilog_tcp(DEBUG, send_packet, LOG_OUTBOUND);

    chitcpd_send_tcp_packet(si, entry, send_packet);

    chitcp_tcp_packet_free(send_packet);
    free(send_packet);
    
    return CHITCP_OK;
}

int handle_TIMEOUT_PST(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    if (circular_buffer_count(&tcp_data->send) != 0)
    {
        /* if the send buffer is not empty, send a probe segment */
        send_probe(si, entry);
    }

    /* note if the send buffer is empty, only reset the persist timer */

    /* reset the timer in both cases */
    worker_args_t *wa = calloc(1, sizeof(worker_args_t));
    wa->si = si;
    wa->entry = entry;;
    mt_set_timer(tcp_data->mt, PERSIST, tcp_data->RTO, persist_callback, (void*) wa);
    return CHITCP_OK;
}

int test_acceptability(tcp_data_t *tcp_data, tcp_packet_t *packet)
{
    int rcv_wnd = tcp_data->RCV_WND;
    int rcv_nxt = tcp_data->RCV_NXT;
    int seg_seq = SEG_SEQ(packet);
    int seg_len = SEG_LEN(packet);
    chilog(TRACE, "SEGLEN in test acceptability: %d", seg_len);

    /* test acceptability according to the table in RFC */
    if (seg_len == 0 && rcv_wnd == 0)
        return seg_seq == rcv_nxt;
    else if (seg_len == 0 && rcv_wnd > 0)
        return rcv_nxt <= seg_seq && seg_seq < rcv_nxt + rcv_wnd;
    else if (seg_len > 0 && rcv_wnd == 0)
        return 0;
    else
        return (rcv_nxt <= seg_seq && seg_seq < rcv_nxt + rcv_wnd) ||
            (rcv_nxt <= seg_seq + seg_len - 1 &&
            seg_seq + seg_len - 1 < rcv_nxt + rcv_wnd);
}

int send_data_in_buffer(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_state_t tcp_state = entry->tcp_state;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* DO NOT USE UINT HERE, they may be negative when handling errors */
    int usable_wnd_sz;
    int num_read = 0;
    int buf_count;
    uint8_t *payload = calloc(TCP_MSS, sizeof(uint8_t));

    /* Read from the send buffer until it's empty or reaches window size */
    /* The buffer_read func will handle the "buffer empty" situation */
    /* Each time we take no more than MSS */
    while (1)
    {
        /* We will use "break" instead of lengthy "while" arguments */
        usable_wnd_sz =
            tcp_data->SND_UNA + tcp_data->SND_WND - tcp_data->SND_NXT;
        chilog(DEBUG, "usable_wnd_sz: %d", usable_wnd_sz);
        if (usable_wnd_sz <= 0)
        {
            break;
        }

        buf_count = circular_buffer_count(&tcp_data->send);
        chilog(DEBUG, "buffer count: %d", buf_count);
        if (buf_count <= tcp_data->SND_NXT - tcp_data->SND_UNA)
        {
            break;
        }
        
        /* note: peek instead of read here */
        num_read = circular_buffer_peek_at(&tcp_data->send, payload, tcp_data->SND_NXT,
                                        MIN(TCP_MSS, usable_wnd_sz));
        chilog(DEBUG, "num_read (aka length of this packet to be sent): %d",
               num_read);
        if (num_read == CHITCP_EINVAL)
        {
            chilog(DEBUG, "buffer empty or invalid sequence number");
            break;
        }

        /* something is read and to be sent */
        tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
        tcphdr_t *send_header;
        chitcpd_tcp_packet_create(entry, send_packet, payload, num_read);
        send_header = TCP_PACKET_HEADER(send_packet);
        send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
        send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        send_header->win = chitcp_htons(tcp_data->RCV_WND);
        send_header->ack = 1;

        tcp_data->SND_NXT += TCP_PAYLOAD_LEN(send_packet);

        chilog(DEBUG, "Sending packet...");
        chilog_tcp(DEBUG, send_packet, LOG_OUTBOUND);

        chitcpd_send_tcp_packet(si, entry, send_packet);
        /* don't free the packet yet */

        retransmit(si, entry, send_packet);
    }
    free(payload);

    /* handle the queued FIN if everything is sent */
    if (circular_buffer_count(&tcp_data->send) == 0 &&
        tcp_data->SND_NXT == tcp_data->SND_UNA && tcp_data->closing)
    {
        /* FIN to be sent */
        send_FIN(si, entry);
        /* mark that the FIN has been sent */
        tcp_data->closing = false;
    }
    return CHITCP_OK;
}

int send_FIN(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    tcphdr_t *send_header;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    send_header = TCP_PACKET_HEADER(send_packet);
    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);
    send_header->ack = 1;
    send_header->fin = 1;

    chilog(DEBUG, "Sending packet...");
    chilog_tcp(DEBUG, send_packet, LOG_OUTBOUND);
    chitcpd_send_tcp_packet(si, entry, send_packet);
    retransmit(si, entry, send_packet);

    tcp_data->SND_NXT++;
    return CHITCP_OK;
}

int send_ACK(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    tcphdr_t *send_header;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    send_header = TCP_PACKET_HEADER(send_packet);
    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);
    send_header->ack = 1;

    chilog(DEBUG, "Sending packet...");
    chilog_tcp(DEBUG, send_packet, LOG_OUTBOUND);
    chitcpd_send_tcp_packet(si, entry, send_packet);

    free(send_packet);
    return CHITCP_OK;
}

int send_SYN(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    tcphdr_t *send_header;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    send_header = TCP_PACKET_HEADER(send_packet);

    /* if tcp_state is CLOSED, send SYN without ACK */
    if (entry->tcp_state == CLOSED)
    {
        send_header->seq = chitcp_htonl(tcp_data->ISS);
        send_header->syn = 1;
    }
    else
    {
        send_header->seq = chitcp_htonl(tcp_data->ISS);
        send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        send_header->win = chitcp_htons(tcp_data->RCV_WND);
        send_header->syn = 1;
        send_header->ack = 1;
    }

    chilog(DEBUG, "Sending packet...");
    chilog_tcp(DEBUG, send_packet, LOG_OUTBOUND);
    chitcpd_send_tcp_packet(si, entry, send_packet);
    retransmit(si, entry, send_packet);
    return CHITCP_OK;
}

int queue_request_FIN(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (tcp_data->SND_UNA == tcp_data->SND_NXT)
    {
        /* everything in the buffer has been sent */
        /* send a empty FIN */
        send_FIN(si, entry);
    }
    tcp_data->closing = TRUE;
    return CHITCP_OK;
}

int handle_RECEIVE(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    tcp_data->RCV_NXT = circular_buffer_next(&tcp_data->recv);
    return CHITCP_OK;
}

int compute_RTO(chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retrans_node_t *node;
    uint64_t RTT = 0;
    struct timespec current_time, diff;
    clock_gettime(CLOCK_REALTIME, &current_time);

    LL_FOREACH(tcp_data->retrans_queue, node)
    {
        if (SEG_SEQ(node->packet) < tcp_data->SND_UNA)
        {
            timespec_subtract(&diff, &current_time, &node->tp);
            RTT = timespec_to_uint(diff);
        }
    }
    if (RTT == 0) return CHITCP_OK;
    if (tcp_data->first)
    {
        tcp_data->SRTT = RTT;
        tcp_data->RTTVAR = RTT / 2;
        tcp_data->first = false;
    }
    else
    {
        tcp_data->RTTVAR = (1 - BETA) * tcp_data->RTTVAR + BETA * abs(tcp_data->SRTT - RTT);
        tcp_data->SRTT = (1 - ALPHA) * tcp_data->SRTT + ALPHA * RTT;
    }
    tcp_data->RTO = MAX(tcp_data->SRTT + MAX(G, K * tcp_data->RTTVAR), MIN_RTO);
    return CHITCP_OK;
}

int timespec_cmp(retrans_node_t *a, retrans_node_t *b) 
{
    if (a->tp.tv_sec > b->tp.tv_sec)
        return 1;
    else if (a->tp.tv_sec < b->tp.tv_sec)
        return -1;

    if (a->tp.tv_nsec > b->tp.tv_nsec)
        return 1;
    else if (a->tp.tv_nsec < b->tp.tv_nsec)
        return -1;
        
    return 0;
}

int seq_cmp(ooo_node_t *a, ooo_node_t *b)
{
    return SEG_SEQ(a->packet) - SEG_SEQ(b->packet);
}

int remove_acked_packets(chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retrans_node_t *node, *tmp;
    LL_FOREACH_SAFE(tcp_data->retrans_queue, node, tmp)
    {
        chilog(DEBUG, "current packet: seq %d:%d", 
            SEG_SEQ(node->packet), SEG_SEQ(node->packet) + TCP_PAYLOAD_LEN(node->packet));
        chilog(DEBUG, "SND.UNA: %d", tcp_data->SND_UNA);
        if (SEG_SEQ(node->packet) < tcp_data->SND_UNA)
        {
            chilog(DEBUG, "packet with seq %d:%d aknowledged, therefore removed from queue", 
                SEG_SEQ(node->packet), SEG_SEQ(node->packet) + TCP_PAYLOAD_LEN(node->packet));
            /* delete the acknowledged data from buffer */
            circular_buffer_read(&tcp_data->send, NULL, TCP_PAYLOAD_LEN(node->packet), FALSE);
            chitcp_tcp_packet_free(node->packet);
            free(node->packet);
            LL_DELETE(tcp_data->retrans_queue, node);
        }
    }

    /* if all packets are acknowledged, stop the timer */
    if (tcp_data->retrans_queue == NULL)
        mt_cancel_timer(tcp_data->mt, 0);

    return CHITCP_OK;
}

int remove_contiguous_packets(chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    ooo_node_t *node, *tmp;

    chilog(DEBUG, "iterating the queue....");
    LL_FOREACH_SAFE(tcp_data->ooo_queue, node, tmp)
    {
        chilog(DEBUG, "current packet: seq %d:%d", 
            SEG_SEQ(node->packet), SEG_SEQ(node->packet) + TCP_PAYLOAD_LEN(node->packet));

        chitcp_packet_list_append(&tcp_data->pending_packets, node->packet);
        LL_DELETE(tcp_data->ooo_queue, node);

        if (node->next)
        {
            if (SEG_SEQ(node->packet) + SEG_LEN(node->packet) != SEG_SEQ(node->next->packet))
                break;
        }
    }
    return CHITCP_OK;
}

void retrans_callback(multi_timer_t *mt, single_timer_t *st, void *data)
{
    chilog(DEBUG, "retransmission timeout");
    worker_args_t *wa = (worker_args_t*) data;
    chitcpd_timeout(wa->si, wa->entry, RETRANSMISSION);
    free(wa);
}

void persist_callback(multi_timer_t *mt, single_timer_t *st, void *data)
{
    chilog(DEBUG, "persist timeout");
    worker_args_t *wa = (worker_args_t*) data;
    chitcpd_timeout(wa->si, wa->entry, PERSIST);
    free(wa);
}

uint64_t timespec_to_uint(struct timespec tp)
{
    return tp.tv_sec * SECOND + tp.tv_nsec * NANOSECOND;
}

int retransmit(serverinfo_t *si, chisocketentry_t *entry, tcp_packet_t *packet)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    /* set the retransmission timer */
    worker_args_t *wa = calloc(1, sizeof(worker_args_t));
    wa->si = si;
    wa->entry = entry;
    mt_set_timer(tcp_data->mt, RETRANSMISSION, tcp_data->RTO, retrans_callback, (void*) wa);

    retrans_node_t *node = calloc(1, sizeof(retrans_node_t));
    node->packet = packet;
    clock_gettime(CLOCK_REALTIME, &node->tp);
    LL_APPEND(tcp_data->retrans_queue, node);
    LL_SORT(tcp_data->retrans_queue, timespec_cmp);
    return CHITCP_OK;
}

void check_zero_window(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t* tcp_data = &entry->socket_state.active.tcp_data;

    single_timer_t *timer;
    mt_get_timer_by_id(tcp_data->mt, PERSIST, &timer);

    /* set the callback arguments */
    worker_args_t *wa = calloc(1, sizeof(worker_args_t));
    wa->si = si;
    wa->entry = entry;

    /* set the persist timer if the advertised window is 0 */
    if (tcp_data->SND_WND == 0)
    {
        if (!mt_is_active(tcp_data->mt, PERSIST))
        {
            mt_set_timer(tcp_data->mt, PERSIST, tcp_data->RTO, persist_callback, (void*) wa);
        }
    }
    else
    {
        /* cancel the persist timer if it's on */
        if (mt_is_active(tcp_data->mt, PERSIST))
        {
            mt_cancel_timer(tcp_data->mt, PERSIST);
            /* note the buffer should be updated based on SND_UNA 
             * so it's handled when receiving ack */
        }
    }
}
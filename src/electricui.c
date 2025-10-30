/* Copyright (c) 2016-2022 Electric UI
 * MIT Licenced - see LICENCE for details.
 *
 * 
 */

#include <string.h>
#include "electricui.h"
#include "eui_utilities.h"

// static functions
static eui_message_t *
find_message_object( const char * search_id, uint8_t is_internal );

static eui_interface_t *
auto_interface( void );

static callback_data_out_t
auto_output( void );

static uint8_t
handle_packet_action(   eui_interface_t *valid_packet,
                        eui_header_t    *header,
                        eui_message_t   *p_msg_obj );

static uint8_t
handle_packet_ack(  eui_interface_t *valid_packet,
                    eui_header_t    *header,
                    eui_message_t   *p_msg_obj );

static uint8_t
handle_packet_query(    eui_interface_t *valid_packet,
                        eui_header_t    *header,
                        eui_message_t   *p_msg_obj );

// Application layer functionality accessed via UI callback
static void
announce_dev_msg( void );

static eui_variable_count_t
send_tracked_message_id_list( void );

static void
send_tracked_variables( void );

static void
announce_dev_msg_2p0( void );

static void
send_default_layout(void) ;




// Communication Interfaces management
static eui_interface_t     *p_interface_arr;
static uint8_t             interface_num;
static eui_interface_t     *p_interface_last;

// Application developer's managed messages
static eui_message_t           *p_dev_tracked;
static eui_variable_count_t    dev_tracked_num;

// eUI variables accessible to developer
static uint8_t     heartbeat;
static uint16_t    board_identifier;
static uint8_t        hostSetup = 0;

static const char* defaultLayout = 0; // Pointer to default layout string

void set_default_layout(const char* layout) {
    defaultLayout = layout;
}


//internal eUI tracked variables
static uint8_t library_version = EUI_LIBRARY_VERSION;

static eui_message_t internal_msg_store[] = 
{
    EUI_UINT8(      EUI_INTERNAL_HEARTBEAT,     heartbeat           ),
    EUI_UINT8_RO(   EUI_INTERNAL_LIB_VER,       library_version     ),
    EUI_UINT16_RO(  EUI_INTERNAL_BOARD_ID,      board_identifier    ),

    EUI_FUNC(   EUI_INTERNAL_AM, announce_dev_msg        ),
    EUI_FUNC(   EUI_INTERNAL_AM2, announce_dev_msg_2p0  ),
    EUI_FUNC(   EUI_INTERNAL_AV, send_tracked_variables  ),
    EUI_FUNC(   EUI_INTERNAL_DEFAULTLAYOUT, send_default_layout  ),
};

// Developer facing search
eui_message_t *
find_tracked_object( const char * search_id )
{
    return find_message_object( search_id, MSG_DEV );
}

// Internal search in either variable array
static eui_message_t * 
find_message_object( const char * search_id, uint8_t is_internal )
{
    eui_message_t *found_obj_ptr = 0;

    if( search_id )
    {
        if( is_internal )
        {
            //search the internal array for matching messageID
            for(eui_variable_count_t i = 0; i < EUI_ARR_ELEM( internal_msg_store ); i++)
            {
                if( strncmp( search_id, internal_msg_store[i].id, EUI_MAX_MSGID_SIZE ) == 0 )
                {
                    found_obj_ptr = &internal_msg_store[i];
                    i = EUI_ARR_ELEM( internal_msg_store );
                }
            }
        }
        else
        {
            //search developer space array for matching messageID
            for(eui_variable_count_t i = 0; i < dev_tracked_num; i++)
            {
                if( strncmp( search_id, p_dev_tracked[i].id, EUI_MAX_MSGID_SIZE ) == 0 )
                {
                    found_obj_ptr = &p_dev_tracked[i];
                    i = dev_tracked_num;
                }
            }
        }
    }

    return found_obj_ptr;
}

static eui_interface_t *
auto_interface( void )
{
    eui_interface_t *p_interface = 0;

    if( interface_num && p_interface_arr && p_interface_last )
    {
        p_interface = p_interface_last;
    }

    return p_interface;
}

static callback_data_out_t
auto_output( void )
{
    eui_interface_t *p_selected_interface = auto_interface();

    if( p_selected_interface )
    {
        return p_selected_interface->output_cb;
    }

    return 0;
}

eui_errors_t
eui_parse( uint8_t inbound_byte, eui_interface_t *p_link )
{
    eui_errors_t status;
    status.parser = eui_decode(inbound_byte, &p_link->packet);

    if( EUI_PARSER_OK == status.parser )
    {
        p_interface_last              = p_link;
        eui_header_t   header_in    = *(eui_header_t*)&p_link->packet.header;
        eui_message_t *p_msglocal   = find_message_object(  (char*)p_link->packet.id_in,
                                                            header_in.internal );

        if( p_msglocal )
        {
            // Running callbacks or write inbound data as required
            status.action = handle_packet_action( p_link, &header_in, p_msglocal );
            // Respond to a request for ack if the action completed successfully
            if( status.action == EUI_ACTION_OK )
            {
                status.ack = handle_packet_ack( p_link, &header_in, p_msglocal );
            }

            // Respond to queries 
            // this includes invalid inbound header types, as we provide 'correct' type info
            status.query = handle_packet_query( p_link, &header_in, p_msglocal );

            // Notify the developer of the tracked message
            if( p_link->interface_cb )
            {
                p_link->interface_cb( EUI_CB_TRACKED );
            }
        }
        else
        {
            if( p_link->interface_cb )
            {
                p_link->interface_cb( EUI_CB_UNTRACKED );
            }
        }

        memset( &p_link->packet, 0, sizeof(eui_packet_t) );
    }
    else if( EUI_PARSER_ERROR == status.parser )
    {
        if( p_link->interface_cb )
        {
            p_link->interface_cb( EUI_CB_PARSE_FAIL );
        }

        memset( &p_link->packet, 0, sizeof(eui_packet_t) );
    }

    return status;
}

static uint8_t
handle_packet_action(   eui_interface_t *valid_packet,
                        eui_header_t    *header,
                        eui_message_t   *p_msg_obj )
{
    uint8_t status = EUI_ACTION_OK;

    uint8_t inbound_type_matches = ((uint8_t)p_msg_obj->type & 0x0Fu) == (uint8_t)header->type;

    if( inbound_type_matches )
    {
        uint8_t is_callback = ((uint8_t)p_msg_obj->type & 0x0Fu) == TYPE_CALLBACK;
        uint8_t is_writable = !((uint8_t)p_msg_obj->type >> 7u);

        uint8_t is_object = ( ( ( p_msg_obj->type & 0x70u ) == 0x60u) || ( ( p_msg_obj->type & 0x70u ) == 0x50u ) ); // Pointer to Object        const void* data_ptr = p_msg_obj->ptr.data;
        const void* data_ptr = p_msg_obj->ptr.data;
        if (is_object && (header->data_len == 0) )  {
            //empty packet, treat as ack
            ack_object(p_msg_obj->ptr.data_editable);
        }

        if( is_callback )
        {
            if(    ((uint8_t)header->response && (uint8_t)header->acknum)
                || (!(uint8_t)header->response && !(uint8_t)header->acknum) )
            {
                // Create a function to call from the internal stored pointer
                eui_cb_t cb_packet_h = p_msg_obj->ptr.callback;

                if( cb_packet_h )
                {
                    cb_packet_h();
                }
                else
                {
                    status = EUI_ACTION_CALLBACK_ERROR;
                }
            }
        }
        else if( valid_packet->packet.parser.data_bytes_in )
        {
            // Ensure data won't exceed bounds with invalid offsets/lengths
            if( is_writable && 
                (valid_packet->packet.offset_in + (uint16_t)header->data_len) <= p_msg_obj->size )
            {
                if (is_object) {
                    // Copy the object to a new object to avoid modifying the original
                    // Expect for data_ptr, use the original for receiving data (and modified for sending)
                    eui_message_t new_msg_obj = *p_msg_obj;
                    data_ptr = ptr_settings_from_object(&new_msg_obj);
                    set_object(&new_msg_obj, valid_packet->packet.offset_in, valid_packet->packet.data_in, header->data_len);
                } else {
                    memcpy( (uint8_t *) data_ptr + valid_packet->packet.offset_in,
                        valid_packet->packet.data_in,
                        header->data_len );
                }
            }
            else
            {
                status = EUI_ACTION_WRITE_ERROR;
            }
        }
    }
    else if( TYPE_OFFSET_METADATA != (uint8_t)header->type )
    {
        status = EUI_ACTION_TYPE_MISMATCH_ERROR;
    }

    return status;
}

static uint8_t
handle_packet_ack(  eui_interface_t *valid_packet,
                    eui_header_t    *header,
                    eui_message_t   *p_msg_obj )
{
    uint8_t status = EUI_ACK_OK;

    if( (uint8_t)header->acknum && (uint8_t)header->response )
    {
        eui_header_t ack_header = { .internal   = header->internal,
                                    .response   = MSG_NRESP,
                                    .type       = p_msg_obj->type,
                                    .id_len     = strlen(p_msg_obj->id),
                                    .acknum     = header->acknum,
                                    .offset     = header->offset,
                                    .data_len   = 0  };

        status = eui_encode(    valid_packet->output_cb,
                                &ack_header,
                                p_msg_obj->id,
                                valid_packet->packet.offset_in,
                                p_msg_obj->ptr.data );

    }

    return status;
}

static uint8_t
handle_packet_query(    eui_interface_t *valid_packet,
                        eui_header_t    *header,
                        eui_message_t   *p_msg_obj )
{
    uint8_t status = EUI_QUERY_OK;

    if( (uint8_t)header->response && !header->acknum )
    {
        // Respond with data to fulfil query behaviour
        eui_pkt_settings_t res_header = { .internal = header->internal,
                                          .response = MSG_NRESP, 
                                          .type     = p_msg_obj->type };

        // inverted logic used to keep ifdef disable clean
        if( TYPE_OFFSET_METADATA != (uint8_t)header->type )
        {
            status = eui_send(valid_packet->output_cb, p_msg_obj, &res_header);
        }
#ifndef EUI_CONF_OFFSETS_DISABLED
        else
        {
            uint16_t base_address = 0;
            uint16_t end_address  = 0;
            
            base_address  = (uint16_t)valid_packet->packet.data_in[1] << 8u;
            base_address |= valid_packet->packet.data_in[0];

            end_address  = (uint16_t)valid_packet->packet.data_in[3] << 8u;
            end_address |= valid_packet->packet.data_in[2];

            status = eui_send_range(    valid_packet->output_cb,
                                        p_msg_obj,
                                        &res_header,
                                        base_address,
                                        end_address ) << 1;
        }
#endif
    }

    return status;
}


uint8_t
eui_send(   callback_data_out_t output_cbtion,
            eui_message_t       *p_msg_obj,
            eui_pkt_settings_t  *settings )
{
    uint8_t status = EUI_OUTPUT_ERROR;
    eui_message_t* local_msg_obj = p_msg_obj;

    if( output_cbtion && p_msg_obj )
    {
        settings->type = p_msg_obj->type;
        uint8_t is_object = ( ( ( p_msg_obj->type & 0x70u ) == 0x60u) || ( ( p_msg_obj->type & 0x70u ) == 0x50u ) ); // Pointer to Object

        eui_message_t new_msg_obj;
        if (is_object) {
            new_msg_obj = *p_msg_obj; //make local copy to avoid modifying original
            local_msg_obj = &new_msg_obj;
            new_msg_obj.ptr.data = ptr_settings_from_object(&new_msg_obj);
        }
        //decide if data will fit in a normal message, or requires multi-packet output
        if( local_msg_obj->size <= OUTBOUND_PAYLOAD_SIZE_MAX )
        {
            status = eui_encode_simple( output_cbtion,
                                        settings,
                                        local_msg_obj->id,
                                        local_msg_obj->size,
                                        local_msg_obj->ptr.data );
        }
#ifndef EUI_CONF_OFFSETS_DISABLED
        else
        {
            status = eui_send_range( output_cbtion,
                                        local_msg_obj,
                                        settings,
                                        0,
                                        local_msg_obj->size );
        }
#endif
    }

    return status;
}

uint8_t
eui_send_range( callback_data_out_t output_cbtion,
                eui_message_t       *p_msg_obj,
                eui_pkt_settings_t  *settings,
                uint16_t            base_addr,
                uint16_t            end_addr )
{
    uint8_t status = EUI_OUTPUT_ERROR;

    uint16_t data_range[2]  = { 0 };
    validate_offset_range(  base_addr,
                            end_addr,
                            (p_msg_obj->type & 0x0Fu),
                            p_msg_obj->size,
                            &data_range[0],
                            &data_range[1]);

    eui_header_t tmp_header = { 0 };
    tmp_header.internal   = settings->internal;
    tmp_header.response   = settings->response;
    tmp_header.id_len     = strlen(p_msg_obj->id);

    //generate metadata message with address range
    tmp_header.data_len     = sizeof(base_addr) * 2; //base and end are sent
    tmp_header.type         = TYPE_OFFSET_METADATA;

    status = eui_encode( output_cbtion, &tmp_header, p_msg_obj->id, 0x00, &data_range);

    //send the offset packets
    tmp_header.offset = 1;
    tmp_header.type   = p_msg_obj->type;

    while( end_addr > base_addr && ( EUI_OUTPUT_OK == status) )
    {
        uint16_t bytes_remaining = end_addr - base_addr;

        if( bytes_remaining > OUTBOUND_PAYLOAD_SIZE_MAX )
        {
            tmp_header.data_len = OUTBOUND_PAYLOAD_SIZE_MAX;
        }
        else
        {
            tmp_header.data_len = bytes_remaining;
        }
        
        //the current position through the buffer in bytes is also the end offset
        end_addr -= (uint16_t)tmp_header.data_len;

        status = eui_encode(    output_cbtion,
                                &tmp_header,
                                p_msg_obj->id,
                                end_addr,
                                p_msg_obj->ptr.data );
    }

    return status;
}

void
eui_send_tracked( const char * msg_id )
{
    if( msg_id )
    {
        eui_pkt_settings_t temp_header = { 0 };
        temp_header.internal  = MSG_DEV;
        temp_header.response  = MSG_NRESP;

        eui_send(   auto_output(),
                    find_message_object( msg_id, MSG_DEV ),
                    &temp_header );
    }
}

void
eui_send_tracked_on(const char * msg_id, eui_interface_t *interface)
{
    if( msg_id && interface )
    {
        eui_pkt_settings_t      temp_header = { 0 };
        temp_header.internal  = MSG_DEV;
        temp_header.response  = MSG_NRESP;

        eui_send(   interface->output_cb,
                    find_message_object( msg_id, MSG_DEV ),
                    &temp_header );
    }
}

void
eui_send_untracked( eui_message_t *p_msg_obj )
{
    if( p_msg_obj )
    {
        eui_pkt_settings_t      temp_header = { 0 };
        temp_header.internal  = MSG_DEV;
        temp_header.response  = MSG_NRESP;

        eui_send(   auto_output(),
                    p_msg_obj,
                    &temp_header );
    }
}

void
eui_send_untracked_on( eui_message_t *p_msg_obj, eui_interface_t *interface )
{
    if( p_msg_obj && interface )
    {
        eui_pkt_settings_t      temp_header = { 0 };
        temp_header.internal  = MSG_DEV;
        temp_header.response  = MSG_NRESP;

        eui_send(   interface->output_cb,
                    p_msg_obj,
                    &temp_header );
    }
}

//application layer developer setup helpers
void
eui_setup_interface( eui_interface_t *p_dev_interface )
{
    eui_setup_interfaces( p_dev_interface, 1 );
}

void
eui_setup_interfaces( eui_interface_t *p_developer_if_arr, uint8_t dev_if_num )
{
    if( p_developer_if_arr && dev_if_num )
    {
        p_interface_arr = p_developer_if_arr;
        interface_num   = dev_if_num;

        // bootstrap the auto_interface with the 0th interface from the array
        p_interface_last = p_developer_if_arr;
    }
    else
    {
        p_interface_arr     = 0;
        interface_num       = 0;
        p_interface_last    = 0;
    }

}

void
eui_setup_tracked( eui_message_t *msg_array, eui_variable_count_t num_tracked )
{
    if( msg_array && num_tracked )
    {
        p_dev_tracked   = msg_array;
        dev_tracked_num = num_tracked;
    }
    else
    {
        p_dev_tracked   = 0;
        dev_tracked_num = 0;
    }
}

void
eui_setup_identifier( char * uuid, uint8_t bytes )
{
    if( uuid && bytes )
    {
        //generate a 'hashed' int16 of their UUID
        for(uint8_t i = 0; i < bytes; i++)
        {
            eui_crc(uuid[i], &board_identifier);
        }
    }
    else
    {
        //a null identifier demonstrates an issue
        board_identifier = 0;
    }
}

//application layer callbacks

static void
announce_dev_msg( void )
{
    hostSetup = 0; // Reset hostSetup to false before sending tracked variables
    eui_variable_count_t num_writable  = 0;
    num_writable = send_tracked_message_id_list();

    eui_pkt_settings_t temp_header = { 0 };
    temp_header.internal  = MSG_INTERNAL;
    temp_header.response  = MSG_NRESP;
    temp_header.type      = TYPE_MANY_VARIABLES_SIZED;
    eui_encode_simple(  auto_output(),
                        &temp_header, 
                        EUI_INTERNAL_AM_END,
                        sizeof(num_writable),
                        &num_writable);
}

static eui_variable_count_t
send_tracked_message_id_list( void )
{
    eui_variable_count_t variables_sent = 0;

    eui_pkt_settings_t temp_header = { 0 };
    temp_header.internal  = MSG_INTERNAL;
    temp_header.response  = MSG_NRESP;
    temp_header.type      = TYPE_CUSTOM;

    uint8_t msgBuffer[ EUI_MAX_MSGID_SIZE*4 ]; // Can fit at least 4 full-size msgID
    uint8_t msg_buffer_position  = 0;  // position in buffer
    uint8_t id_len               = 0;  // length of a single id string
    uint8_t id_packed_num        = 0;  // count messages packed into buffer

    for( eui_variable_count_t i = 0; i < dev_tracked_num; i++ )
    {
        //copy messageID into the buffer, account for null termination characters as delimiter
        id_len = strlen(p_dev_tracked[i].id) + 1;
        memcpy(msgBuffer+msg_buffer_position, p_dev_tracked[i].id, id_len);
        msg_buffer_position += id_len;
        id_packed_num++;

        variables_sent++;
            
        //send messages and clear buffer if the buffer can't fit the next one or is finished
        if( (dev_tracked_num - 1 <= i) || ( (sizeof(msgBuffer) - strlen(p_dev_tracked[i + 1].id) - 1) < msg_buffer_position) )
        {
            eui_encode_simple(  auto_output(),
                                &temp_header,
                                EUI_INTERNAL_AM_LIST,
                                msg_buffer_position,
                                &msgBuffer );

            //cleanup
            memset(msgBuffer, 0, sizeof(msgBuffer));
            msg_buffer_position = 0;
            id_packed_num  = 0;
        }
    }

    return variables_sent;
}

static void
send_tracked_variables( void )
{
    eui_pkt_settings_t      temp_header = { 0 };

    temp_header.internal    = MSG_DEV;
    temp_header.response    = MSG_NRESP;

    for(eui_variable_count_t i = 0; i < dev_tracked_num; i++)
    {
        eui_send( auto_output(), p_dev_tracked + i, &temp_header );
        eui_message_t* m = p_dev_tracked + i;
        if ( ( (m->type & 0x70u) == 0x60u) || ( (m->type & 0x70u) == 0x50u) ) {
            //reset ack status on an objects when send_tracked_variables ('w') is called
            ack_object(m->ptr.data_editable);
        }
    }
    hostSetup = 1; // Set hostSetup to true after sending all tracked variables
}

static void send_default_layout(void) {
    if (defaultLayout) {
        uint8_t status = EUI_OUTPUT_ERROR;

        size_t remaining = strlen(defaultLayout)+1; //+1 for null terminator
        uint16_t data_range[2]  = { 0 };
        eui_header_t chunk_header = { 0 };

        chunk_header.internal  = MSG_INTERNAL;
        chunk_header.response  = MSG_NRESP;
        chunk_header.type      = TYPE_OFFSET_METADATA;
        chunk_header.id_len    = 1;
        chunk_header.data_len  = sizeof(data_range); //base and end are sent

        data_range[1] = remaining > UINT16_MAX ? UINT16_MAX : (uint16_t) remaining; //end address

        status = eui_encode( auto_output(), &chunk_header, EUI_INTERNAL_DEFAULTLAYOUT_REPLY, 0x00, &data_range);

        chunk_header.offset    = 1;
        chunk_header.type      = TYPE_CHAR;

        while (remaining > 0 && EUI_OUTPUT_OK == status) {

            // Calculate size for this chunk
            size_t chunk_size = remaining % OUTBOUND_PAYLOAD_SIZE_MAX;
            if (chunk_size == 0) {
                chunk_size = OUTBOUND_PAYLOAD_SIZE_MAX;
            }

            chunk_header.data_len = chunk_size;
            remaining -= chunk_size;

            status = encode_packet(    auto_output(),
                                &chunk_header,
                                EUI_INTERNAL_DEFAULTLAYOUT_REPLY,
                                remaining,
                                defaultLayout);
        }
    } else {
        eui_header_t chunk_header = { 0 };
        chunk_header.internal  = MSG_INTERNAL;
        chunk_header.response  = MSG_NRESP;
        chunk_header.type      = TYPE_CHAR;
        chunk_header.id_len    = 1;
        chunk_header.data_len  = 1;

        encode_packet(auto_output(),
                         &chunk_header,
                                EUI_INTERNAL_DEFAULTLAYOUT_REPLY,
                                1,
                                &defaultLayout);
    }
}


static void
announce_dev_msg_2p0( void ) {
    hostSetup = 0; // Reset hostSetup to false before sending tracked variables
    eui_pkt_settings_t temp_header = { 0 };
    temp_header.internal  = MSG_INTERNAL;
    temp_header.response  = MSG_NRESP;
    temp_header.type      = TYPE_MANY_VARIABLES_SIZED;
    eui_encode_simple(  auto_output(),
                        &temp_header,
                        EUI_INTERNAL_AM_END,
                        sizeof(dev_tracked_num),
                        &dev_tracked_num);

    eui_variable_count_t variables_sent = 0;

    temp_header.internal  = MSG_INTERNAL;
    temp_header.response  = MSG_NRESP;
    temp_header.type      = TYPE_CUSTOM;

    uint8_t msgBuffer[ EUI_MAX_MSGID_SIZE*4 ]; // Can fit at least 4 full-size msgID
    uint8_t msg_buffer_position  = 0;  // position in buffer
    uint8_t id_len               = 0;  // length of a single id string
    uint8_t id_packed_num        = 0;  // count messages packed into buffer

    for( eui_variable_count_t i = 0; i < dev_tracked_num; i++ )
    {
        //copy messageID into the buffer, account for null termination characters as delimiter
        id_len = strlen(p_dev_tracked[i].id) + 1;
        memcpy(msgBuffer+msg_buffer_position, p_dev_tracked[i].id, id_len);
        msg_buffer_position += id_len;
        msgBuffer[msg_buffer_position++] = p_dev_tracked[i].type;
        msgBuffer[msg_buffer_position++] = p_dev_tracked[i].size & 0xFF;
        msgBuffer[msg_buffer_position++] = p_dev_tracked[i].size >> 8;
        id_packed_num++;
        variables_sent++;

         // Check if current variable is an object and reset its ack status
        if (((p_dev_tracked[i].type & 0x70u) == 0x60u) || ((p_dev_tracked[i].type & 0x70u) == 0x50u)) {
            ack_object(p_dev_tracked[i].ptr.data_editable);
        }

        //send messages and clear buffer if the buffer can't fit the next one or is finished
        //subtract string length, minus 1 for null terminator, subtract another one for type and 2 more for size.
        if( (dev_tracked_num - 1 <= i) || ( (sizeof(msgBuffer) - strlen(p_dev_tracked[i + 1].id) - 1 - 1 -2 ) < msg_buffer_position) )
        {
            eui_encode_simple(  auto_output(),
                                &temp_header,
                                EUI_INTERNAL_AM2_REPLY,
                                msg_buffer_position,
                                &msgBuffer );

            //cleanup
            memset(msgBuffer, 0, sizeof(msgBuffer));
            msg_buffer_position = 0;
            id_packed_num  = 0;
        }
    }

    // After sending all tracked variables, send list of values of key / maps
    for( eui_variable_count_t i = 0; i < dev_tracked_num; i++ ) {
        if ((p_dev_tracked[i].type & 0x70u) == 0x50u) {
            uint8_t totalElements = number_of_valid_entries(p_dev_tracked[i].ptr.data);
            uint8_t offset = strlen(p_dev_tracked[i].id)+1; //+1 for null terminator
            if (offset >= sizeof(msgBuffer)) {
                offset = sizeof(msgBuffer) - 1;
            }
            memcpy(msgBuffer, p_dev_tracked[i].id, offset);
            temp_header.type      = TYPE_CHAR;
            for (uint8_t j = 0; j < totalElements; j++) {
                //msgBuffer[offset] = totalElements; // write one byte for size of data
                uint16_t bytes_to_write = list_or_key_pair(p_dev_tracked[i].ptr.data,j, (char*) &msgBuffer[offset], sizeof(msgBuffer)-offset);

                if (bytes_to_write != 0) {
                    encode_packet_simple(  auto_output(),
                            &temp_header,
                            EUI_INTERNAL_GET_KEYS_PAIR,
                            bytes_to_write + offset,
                            &msgBuffer);
                }
            }
        }
    }
}

void send_update_on_tracked_variable(eui_variable_count_t i) {
    eui_pkt_settings_t      temp_header = { 0 };

    temp_header.internal    = MSG_DEV;
    temp_header.response    = MSG_RESP;
    eui_send( auto_output(), p_dev_tracked + i, &temp_header );
}

__attribute__((weak))
const void* ptr_settings_from_object_default(eui_message_t *p_msg_obj) {
    //DOES NOTHING. Should be overridden by external function handling pointers to objects.
    return p_msg_obj->ptr.data;
}
const void* ptr_settings_from_object(eui_message_t *p_msg_obj)
    __attribute__((weak, alias("ptr_settings_from_object_default")));

__attribute__((weak))
void set_object_default(eui_message_t *p_msg_obj, uint16_t offset, uint8_t *data_in, uint16_t len) {
    //DOES NOTHING. Should be overridden by external function handling pointers to objects.
    return;
}

__attribute__((weak))
uint8_t number_of_valid_entries_default(const void *ptr) {return 0;}

uint8_t number_of_valid_entries(const void *ptr)
    __attribute__((weak, alias("number_of_valid_entries_default")));


void set_object(eui_message_t *p_msg_obj, uint16_t offset, uint8_t *data_in, uint16_t len)
    __attribute__((weak, alias("set_object_default")));


__attribute__((weak))
uint16_t list_or_key_pair_default(const void* ptr, uint8_t index, char* msgBuffer, uint16_t bufferSize) { return 0; }

uint16_t list_or_key_pair(const void* ptr, uint8_t index, char* msgBuffer, uint16_t bufferSize)
    __attribute__((weak, alias("list_or_key_pair_default")));


__attribute__((weak))
void ack_object_default(void* ptr) {
    //DOES NOTHING. Should be overridden by external function handling pointers to objects.
    return;
}

void ack_object(void *ptr)
    __attribute__((weak, alias("ack_object_default")));



    __attribute__((weak))
void reset_object_default(void* ptr) {
    //DOES NOTHING. Should be overridden by external function handling pointers to objects.
    return;
}

void reset_object(void *ptr)
    __attribute__((weak, alias("reset_object_default")));


// Query if host setup is done.
uint8_t eui_get_host_setup(void) {
    return hostSetup;
}

uint8_t eui_get_heartbeat( void ) {
    return heartbeat;
}

// END electricui.c
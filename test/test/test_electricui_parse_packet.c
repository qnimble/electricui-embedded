#include "unity.h"
#include <string.h>

// MODULE UNDER TEST
#include "electricui.h"
#include "electricui_private.h"
#include "mock_eui_serial_transport.h"
#include "mock_eui_crc.h"
#include "eui_offset_validation.h"

// DEFINITIONS 
void stub_output_func( uint8_t byte );

// PRIVATE TYPES
 
// PRIVATE DATA
uint8_t interface_cb_hit = 0;
uint8_t interface_cb_arg[5] = { 0 };

uint8_t test_cb_hit = 0;

void test_cb( void )
{
    test_cb_hit++;
}

//developer-space messages
uint8_t test_uint       = 20;
uint8_t test_array[250] = { 20 };

eui_message_t test_dev_msg[] = {
    //simple objects with mostly garbage data, we only care about the ID's
    { .msgID = "data", .type = TYPE_UINT8,      .size = sizeof(test_uint),  .payload = &test_uint   },
    { .msgID = "cb",   .type = TYPE_CALLBACK,   .size = 1,                  .payload = &test_cb     },
    { .msgID = "nocb", .type = TYPE_CALLBACK,   .size = 1,                  .payload = 0     },
    { .msgID = "ofst", .type = TYPE_UINT8,      .size = sizeof(test_array), .payload = &test_array  },
   
    { .msgID = "dataro", .type = TYPE_UINT8|READ_ONLY_MASK, .size = sizeof(test_uint),  .payload = &test_uint },
};

eui_interface_t test_interface = { 0 };
eui_packet_t * test_pk_ptr;             //convenient pointer to parser data inside the interface

// PRIVATE FUNCTIONS

void stub_output_func( uint8_t byte )
{
    //do nothing with it...
}

void stub_user_cb( uint8_t flag )
{
    if(interface_cb_hit < sizeof(interface_cb_arg))
    {
        interface_cb_arg[interface_cb_hit] = flag;
    }

    interface_cb_hit++;
}


// SETUP, TEARDOWN

void setUp(void)
{
    //run before each test
    memset(&test_interface, 0, sizeof(test_interface));
    test_interface.output_func  = &stub_output_func;
    test_interface.interface_cb = &stub_user_cb;
    test_pk_ptr = &test_interface.packet;
    setup_dev_msg(test_dev_msg, ARR_ELEM(test_dev_msg));

    setup_interface( &test_interface, 1);


    test_uint = 20;
    test_cb_hit = 0;
    interface_cb_hit = 0;
    memset(&interface_cb_arg, 0, sizeof(interface_cb_arg));

}
 
void tearDown(void)
{

}

// TESTS

// byte input which doesn't complete a valid packet
void test_ingest_unfinished( void )
{
    // checking idle means we don't really need any faked internal info
    test_pk_ptr->parser.state           = 0;
    test_pk_ptr->parser.id_bytes_in     = 0;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    //expects a 'idle' code returned
    decode_packet_ExpectAndReturn( 0xAF, &test_interface.packet, 0);
    TEST_ASSERT_EQUAL_INT8( status_ok , parse_packet( 0xAF, &test_interface ) );
    
    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_hit );
}

// packet with a malformed crc, etc
void test_ingest_error( void )
{
    //pre-populate part of a valid message
    test_pk_ptr->parser.state           = exp_data;
    test_pk_ptr->parser.id_bytes_in     = 0;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    //put some values inside the packet which we expect to be wiped
    test_pk_ptr->header.data_len    = 6;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.id_len      = 3;

    decode_packet_ExpectAndReturn( 0xAB, &test_interface.packet, parser_error);

    //expect the parse_packet to return an error to the user
    TEST_ASSERT_EQUAL_INT8( status_parser_generic , parse_packet( 0xAB, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 1, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( cb_parse_failure, interface_cb_arg[0] );

    //we expect the handler to wipe the packet handler data after an error
    eui_packet_t blank_packet = { 0 };
    TEST_ASSERT_EQUAL_INT8_ARRAY(&blank_packet, test_pk_ptr, sizeof(eui_packet_t));
}

// packet with a msgID not in our tracked list
void test_ingest_unknown_id( void )
{
    test_pk_ptr->parser.state           = exp_data;   //somewhat meaningless
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 1;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "unkn", 4);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0x0A;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( status_unknown_id , parse_packet( 0x00, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 1 , interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( cb_untracked , interface_cb_arg[0] );

    // handler should clean up after itself
    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// simple packet with some data to write
void test_ingest_data_packet( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "data", 4);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0x0A;

    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    //inbound byte is written to the local variable
    TEST_ASSERT_EQUAL_INT8(0x0A, test_uint);

    TEST_ASSERT_EQUAL_INT8( 1 , interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( cb_tracked , interface_cb_arg[0] );

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// write a new value to the heartbeat internal byte
void test_ingest_data_packet_internal( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 1;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 1;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 1;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "h", 2);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0x02;

    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 2 , heartbeat );

    TEST_ASSERT_EQUAL_INT8( 1 , interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( cb_tracked , interface_cb_arg[0] );

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// simple packet with some data to write
void test_ingest_data_packet_readonly( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 6;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 6;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "dataro", 6);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0x0A;

    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    //inbound byte is should not be written
    TEST_ASSERT_EQUAL_INT8(20, test_uint);

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// inbound payload is larger than the internal variable
void test_ingest_data_packet_exceeds_size( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 4;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 4;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "data", 4);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0x12;
    test_pk_ptr->data_in[1] = 0x34;
    test_pk_ptr->data_in[2] = 0x56;
    test_pk_ptr->data_in[3] = 0x78;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( 4 , parse_packet( 0x00, &test_interface ) );
    //status_offset_er
    //inbound byte shouldn't be written to the local variable - check existing value intact
    TEST_ASSERT_EQUAL_INT8( 20, test_uint);

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// offset packet with target range outside variable bounds
void test_ingest_data_packet_exceeds_range( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 1;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "data", 4);
    test_pk_ptr->offset_in = 2;
    test_pk_ptr->data_in[0] = 0x12;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( 4 , parse_packet( 0x00, &test_interface ) );
    //status_offset_er
    //inbound byte shouldn't be written to the local variable - check existing value intact
    TEST_ASSERT_EQUAL_INT8( 20, test_uint);

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// packet is querying a variable 
void test_ingest_response_packet_query( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 1;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "data", 4);
    test_pk_ptr->offset_in = 2;
    test_pk_ptr->data_in[0] = 0x12;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    encode_packet_simple_ExpectAnyArgsAndReturn( 0 );
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    //only querying... check existing value intact
    TEST_ASSERT_EQUAL_INT8( 20, test_uint);

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// packet is querying a range of data 
void test_ingest_response_packet_query_offset( void )
{
    // inbound message is a offset_metadata message which contains start 
    // and end addresses being questioned
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 4;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 4;
    test_pk_ptr->header.type        = TYPE_OFFSET_METADATA;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 1;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "ofst", 4);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->crc_in = 0xfefe;

    // our data is 350 element uint8 array, lets ask for values between the 40th and 190th values
    test_pk_ptr->data_in[0] = 40; //base address uint16
    test_pk_ptr->data_in[1] = 0;
    test_pk_ptr->data_in[2] = 190; //end address uint16
    test_pk_ptr->data_in[3] = 0;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    //we include the actual validation function, mocking that is busy-work

    //offset outbound has 1x meta-message, + 150bytes into 120b messages for 2x data packets
    for(uint16_t i = 0; i < 3; i++)
    {
        encode_packet_ExpectAnyArgsAndReturn( 0 );
    }
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    //only querying... check existing value intact
    uint8_t ground_truth[250] = { 20 };
    TEST_ASSERT_EQUAL_INT8_ARRAY( ground_truth, test_array, sizeof(ground_truth));

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// packet wants ack response
void test_ingest_response_packet_ack( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 1;
    test_pk_ptr->header.acknum      = 2;

    memcpy(&test_pk_ptr->msgid_in, "data", 4);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0x0E;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    encode_packet_ExpectAnyArgsAndReturn( 0 );
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 0x0E, test_uint);

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// packet is just a callback, no data, no response
void test_ingest_callback_packet_silent( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 2;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 2;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "cb", 2);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 20, test_uint);
    TEST_ASSERT_EQUAL_INT8( 1, test_cb_hit);    //check our callback has been called

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// see what happens when they don't give us a valid pointer for the callback
void test_ingest_callback_packet_silent_invalid( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 4;
    test_pk_ptr->header.response    = 0;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "nocb", 4);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    TEST_ASSERT_EQUAL_INT8( 4 , parse_packet( 0x00, &test_interface ) );
    //status_missing_callback

    TEST_ASSERT_EQUAL_INT8( 20, test_uint);
    TEST_ASSERT_EQUAL_INT8( 0, test_cb_hit);    //check our callback has been called

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

//callback with ack
void test_ingest_callback_packet_ack( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 2;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 2;
    test_pk_ptr->header.response    = 1;
    test_pk_ptr->header.acknum      = 2;

    memcpy(&test_pk_ptr->msgid_in, "cb", 2);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);    
    encode_packet_ExpectAnyArgsAndReturn( 0 );
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 20, test_uint);
    TEST_ASSERT_EQUAL_INT8( 1, test_cb_hit);    //check our callback has been called

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

// when processing a query for a callback, make sure it isn't called as well
void test_ingest_callback_packet_query( void )
{
    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 2;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.offset      = 0;
    test_pk_ptr->header.id_len      = 2;
    test_pk_ptr->header.response    = 1;
    test_pk_ptr->header.acknum      = 0;

    memcpy(&test_pk_ptr->msgid_in, "cb", 2);
    test_pk_ptr->offset_in = 0;
    test_pk_ptr->data_in[0] = 0;
    test_pk_ptr->crc_in = 0xfefe;

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);    
    encode_packet_simple_ExpectAnyArgsAndReturn( 0 );
    TEST_ASSERT_EQUAL_INT8( status_known_id , parse_packet( 0x00, &test_interface ) );

    TEST_ASSERT_EQUAL_INT8( 20, test_uint);
    TEST_ASSERT_EQUAL_INT8( 0, test_cb_hit);    //check our callback has been called

    TEST_ASSERT_EQUAL( 0 , test_pk_ptr->parser.state);
}

void test_ingest_interface_callback_handshake( void )
{

    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 1;
    test_pk_ptr->parser.data_bytes_in   = 0;

    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.internal    = 1;
    test_pk_ptr->header.id_len      = 1;
    memcpy(&test_pk_ptr->msgid_in, EUI_INTERNAL_SEARCH, 1);

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    encode_packet_simple_ExpectAnyArgsAndReturn(0);
    encode_packet_simple_ExpectAnyArgsAndReturn(0);
    encode_packet_simple_ExpectAnyArgsAndReturn(0);

    parse_packet( 0x00, &test_interface );

    //callbacks expected
    TEST_ASSERT_EQUAL_INT8( 2, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( cb_handshake, interface_cb_arg[0] );
    TEST_ASSERT_EQUAL_INT8( cb_tracked, interface_cb_arg[1] );
}

// validate the developer interface space callbacks don't fire when not set
void test_ingest_interface_callback_tracked_invalid( void )
{
    test_interface.interface_cb = 0;

    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.id_len      = 4;
    memcpy(&test_pk_ptr->msgid_in, "data", 4);

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    parse_packet( 0x00, &test_interface );

    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_arg[0] );
}

void test_ingest_interface_callback_untracked_invalid( void )
{
    test_interface.interface_cb = 0;

    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 4;
    test_pk_ptr->parser.data_bytes_in   = 1;

    test_pk_ptr->header.data_len    = 1;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.id_len      = 4;
    memcpy(&test_pk_ptr->msgid_in, "rand", 4);

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    parse_packet( 0x00, &test_interface );

    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_arg[0] );
}

void test_ingest_interface_callback_error_invalid( void )
{
    test_interface.interface_cb = 0;

    test_pk_ptr->parser.state           = exp_data;
    test_pk_ptr->parser.id_bytes_in     = 0;
    test_pk_ptr->parser.data_bytes_in   = 0;
    test_pk_ptr->parser.frame_offset    = 0;

    test_pk_ptr->header.data_len    = 6;
    test_pk_ptr->header.type        = TYPE_UINT8;
    test_pk_ptr->header.internal    = 0;
    test_pk_ptr->header.id_len      = 3;

    decode_packet_ExpectAndReturn( 0xAB, &test_interface.packet, parser_error);
    parse_packet( 0xAB, &test_interface );

    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_arg[0] );
}

void test_ingest_interface_callback_handshake_no_ptr( void )
{
    //no dev callback, but the interface is still live
    test_interface.interface_cb = 0;

    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 1;
    test_pk_ptr->parser.data_bytes_in   = 0;

    test_pk_ptr->header.internal    = 1;
    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.id_len      = 1;
    memcpy(&test_pk_ptr->msgid_in, EUI_INTERNAL_SEARCH, 1);

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    encode_packet_simple_ExpectAnyArgsAndReturn(0);
    encode_packet_simple_ExpectAnyArgsAndReturn(0);
    encode_packet_simple_ExpectAnyArgsAndReturn(0);

    parse_packet( 0x00, &test_interface );

    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_arg[0] );
}

void test_ingest_interface_callback_handshake_no_interface( void )
{
    // with no configured interface, the print output function won't operate
    // this test is included because previously had segfaults when the interface wasn't
    // setup prior to testing a null user callbacks
    
    setup_interface( 0, 0); //nulls out the setup in the TEST_SETUP()
    test_interface.interface_cb = 0;

    test_pk_ptr->parser.state           = exp_crc_b2;
    test_pk_ptr->parser.id_bytes_in     = 1;
    test_pk_ptr->parser.data_bytes_in   = 0;

    test_pk_ptr->header.internal    = 1;
    test_pk_ptr->header.data_len    = 0;
    test_pk_ptr->header.type        = TYPE_CALLBACK;
    test_pk_ptr->header.id_len      = 1;
    memcpy(&test_pk_ptr->msgid_in, EUI_INTERNAL_SEARCH, 1);

    decode_packet_ExpectAndReturn( 0x00, &test_interface.packet, parser_complete);
    //no output function means no printed handshake calls
    parse_packet( 0x00, &test_interface );

    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_hit );
    TEST_ASSERT_EQUAL_INT8( 0, interface_cb_arg[0] );

}
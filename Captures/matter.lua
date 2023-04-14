
-- Author: Simon Kelly
-- Date: April 2023
-- Use at your own risk!

-- Useful links for Wireshark Lua dissector implementations
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
-- http://alex-ii.github.io/tech/2018/05/08/dissector_for_Wireshark_udp.html
-- https://www.golinuxcloud.com/wireshark-dissector-tutorial/
-- https://github.com/kynesim/wireshark/blob/master/test/lua/proto.lua
-- https://github.com/Tanganelli/wireshark-lwm2m/blob/master/lwm2m.lua

-- Define protocol for wireshark
local proto_matter = Proto.new("matter",  "Matter Protocol")

-- Protocol ID definitions
local protocol_id = {
    SECURE_CHANNEL = 0x0000,
    INTERACTION_MODEL = 0x0001,
    BDX = 0x0002,
    USER_DIRECTED_COMMISSIONING = 0x0003,
    TESTING = 0x0004
}
local protocol_id_display = {
	[protocol_id.SECURE_CHANNEL] 				= "Secure Channel",
	[protocol_id.INTERACTION_MODEL] 			= "Interaction Model",
	[protocol_id.BDX] 							= "BDX",
	[protocol_id.USER_DIRECTED_COMMISSIONING] 	= "User Directed Commissioning",
	[protocol_id.TESTING] 						= "Testing",	
}

-- Opcodes: Secure Channel
local opcodes_0 = {
	MSG_COUNTER_SYNC_REQ 	= 0x00,
	MSG_COUNTER_SYNC_RESP 	= 0x01,
	MRP_STANDALONE_ACK	 	= 0x10,
	PBKDF_PARAM_REQ		 	= 0x20,
	PBKDF_PARAM_RESP	 	= 0x21,
	PASE_PAKE1			 	= 0x22,
	PASE_PAKE2			 	= 0x23,
	PASE_PAKE3			 	= 0x24,
	CASE_SIGMA_1		 	= 0x30,
	CASE_SIGMA_2		 	= 0x31,
	CASE_SIGMA_3		 	= 0x32,
	CASE_SIGMA_2_RESUME 	= 0x33,
	STATUS_REPORT	 		= 0x40
}

local opcodes_0_display = {
	[opcodes_0.MSG_COUNTER_SYNC_REQ] 	= "MsgCounterSyncReq",
	[opcodes_0.MSG_COUNTER_SYNC_RESP] 	= "MsgCounterSyncRsp",
	[opcodes_0.MRP_STANDALONE_ACK] 		= "MRP Standalone Acknowledgement",
	[opcodes_0.PBKDF_PARAM_REQ] 		= "PBKDFParamRequest",
	[opcodes_0.PBKDF_PARAM_RESP] 		= "PBKDFParamResponse",
	[opcodes_0.PASE_PAKE1] 				= "PASE Pake1",
	[opcodes_0.PASE_PAKE2] 				= "PASE Pake2",
	[opcodes_0.PASE_PAKE3] 				= "PASE Pake3",
	[opcodes_0.CASE_SIGMA_1] 			= "CASE Sigma1",
	[opcodes_0.CASE_SIGMA_2] 			= "CASE Sigma2",
	[opcodes_0.CASE_SIGMA_3] 			= "CASE Sigma3",
	[opcodes_0.CASE_SIGMA_2_RESUME] 	= "CASE Sigma2_Resume",
	[opcodes_0.STATUS_REPORT] 			= "Status Report"
}

-- Opcodes: Interaction Model
local opcodes_1 = {
	STATUS_RESP 	= 0x01,
	READ_REQ 		= 0x02,
	SUBSCRIBE_REQ	= 0x03,
	SUBSCRIBE_RESP 	= 0x04,
	REPORT_DATA	 	= 0x05,
	WRITE_REQ		= 0x06,
	WRITE_RESP		= 0x07,
	INVOKE_REQ	 	= 0x08,
	INVOKE_RESP		= 0x09,
	TIMED_REQ	 	= 0x0A
}

local opcodes_1_display = {
	[opcodes_1.STATUS_RESP] = "Status Response",
	[opcodes_1.READ_REQ] = "Read Request",
	[opcodes_1.SUBSCRIBE_REQ] = "Subscribe Request",
	[opcodes_1.SUBSCRIBE_RESP] = "Subscribe Response",
	[opcodes_1.REPORT_DATA] = "Report Data",
	[opcodes_1.WRITE_REQ] = "Write Request",
	[opcodes_1.WRITE_RESP] = "Write Response",
	[opcodes_1.INVOKE_REQ] = "Invoke Request",
	[opcodes_1.INVOKE_RESP] = "Invoke Response",
	[opcodes_1.TIMED_REQ] = "Timed Request"
}

-- Opcodes: BDX
local opcodes_2 = {
	SEND_INIT 		= 0x01,
	SEND_ACCEPT 	= 0x02,
	RECEIVE_INIT 	= 0x04,
	RECEIVE_ACCEPT 	= 0x05,
	BLOCK_QUERY 	= 0x10,
	BLOCK 			= 0x11,
	BLOCK_EOF 		= 0x12
}

local opcodes_2_display = {
	[opcodes_2.SEND_INIT] = "SendInit",
	[opcodes_2.SEND_ACCEPT] = "SendAccept",
	[opcodes_2.RECEIVE_INIT] = "ReceiveInit",
	[opcodes_2.RECEIVE_ACCEPT] = "ReceiveAccept",
	[opcodes_2.BLOCK_QUERY] = "BlockQuery",
	[opcodes_2.BLOCK] = "Block",
	[opcodes_2.BLOCK_EOF] = "BlockEOF"
}

-- Opcodes: User Directed Commissioning
local opcodes_3 = {
	IDENTIFICATION_DECLARATION = 0x00
}
local opcodes_3_display = {
	[opcodes_3.IDENTIFICATION_DECLARATION] = "IdentificationDeclaration"
}

--- Generic tables ---
local yes_no_table = {
	[1] = "yes", -- 1=TRUE
	[2] = "no"   -- 2=FALSE
}
local yes_no_warning_table = {
	[1] = "yes (NOT HANDLED BY PLUGIN!)", -- 1=TRUE
	[2] = "no"   -- 2=FALSE
}
local on_off_table = {
	[1] = "on",  -- 1=TRUE
	[2] = "off"  -- 2=FALSE
}

--- Protocol Fields ---

-- Message Flags
local field_message_flags = ProtoField.uint8("matter.message_flags", "Message Flags", base.HEX)

-- Message Flag: Version
local field_message_flag_version = ProtoField.uint8("matter.message_flag_version", "Version", base.HEX, nil, 0xF0, "Protocol version")

-- Message Flag: Source node
local field_message_flag_source_node = ProtoField.bool("matter.message_flag_source_node", "Source Node", 8, yes_no_table, 0x04, "Source Node Present")

-- Message Flag: dsiz
local message_flag_dsiz_table = {
	[0] = "Destination Node ID not present",
	[1] = "Destination Node ID present 64-bit",
	[2] = "Destination Node ID present 16-bit",
	[3] = "Reserved"
}
local field_message_flag_dsiz = ProtoField.uint8("matter.message_flag_dsiz", "dsiz", base.HEX, message_flag_dsiz_table, 0x03, "Destination node")

-- Session ID
local field_session_id = ProtoField.uint16("matter.session_id", "Session ID", base.DEC)

-- Security Flags
local field_security_flags = ProtoField.uint8("matter.security_flags", "Security Flags", base.HEX)

-- Security Flag: Privacy Enhancements
local field_security_flag_p = ProtoField.bool("matter.security_flag_p", "Privacy Enhancements", 8, yes_no_table, 0x80)

-- Security Flag: Control Message
local field_security_flag_c = ProtoField.bool("matter.security_flag_c", "Control Message", 8, yes_no_table, 0x40)

-- Security Flag: Message Extensions
local field_security_flag_mx = ProtoField.bool("matter.security_flag_mx", "Message Extensions", 8, yes_no_warning_table, 0x20)

-- Security Flag: Session Type
local session_type_table = {
	[0] = "Unicast",
	[1] = "Group",
	[2] = "Reserved",
	[3] = "Reserved"
}
local field_security_flag_session_type = ProtoField.uint8("matter.security_flag_session_type", "Session Type", base.HEX, session_type_table, 0x03)

-- Message Counter
local field_message_counter = ProtoField.uint32("matter.message_counter", "Message Counter", base.DEC)

-- Source Node ID
local field_source_node_id = ProtoField.uint64("matter.source_node_id", "Source Node", base.DEC)

-- Destination Node ID 64
local field_destination_node_id_64 = ProtoField.uint64("matter.destination_node_id", "Destination Node", base.DEC)

-- Destination Node ID 16
local field_destination_node_id_16 = ProtoField.uint16("matter.destination_node_id_16", "Destination Node 16-bit", base.DEC)

-- Message Extensions: Ignored!

-- Message payload
local field_message_payload = ProtoField.bytes("matter.message_payload", "Message Payload")

-- Message Integrity (Footer)
local field_message_integrity = ProtoField.bytes("matter.message_integrity", "Message Integrity")

-- Generated field Sample: Message Type - Human readable description of message
local generated_message_type = ProtoField.string("matter.message_type", "Message Type")
local generated_debug_message = ProtoField.string("matter.debug_message", "Debug")
local generated_tlv = ProtoField.string("matter.tlv", "TLV")
local generated_status_report = ProtoField.string("matter.status_report", "Status Report")

-- Exchange Flags
local field_exchange_flags = ProtoField.uint8("matter.exchange_flags", "Exchange Flags", base.HEX)

-- Exchange	 Flag: Initiator
local field_exchange_flag_i = ProtoField.bool("matter.exchange_flag_i", "Initiator", 8, yes_no_table, 0x01)

-- Exchange	 Flag: Acknowledgement
local field_exchange_flag_a = ProtoField.bool("matter.exchange_flag_a", "Acknowledgement", 8, yes_no_table, 0x02)

-- Exchange	 Flag: Reliability
local field_exchange_flag_r = ProtoField.bool("matter.exchange_flag_r", "Reliability", 8, yes_no_table, 0x04)

-- Exchange	 Flag: Secured Extensions
local field_exchange_flag_sx = ProtoField.bool("matter.exchange_flag_sx", "Secured Extensions", 8, yes_no_warning_table, 0x08)

-- Exchange	 Flag: Vendor
local field_exchange_flag_v = ProtoField.bool("matter.exchange_flag_v", "Vendor ID", 8, yes_no_table, 0x10)

-- Opcodes
local field_opcode_0 = ProtoField.uint8("matter.opcode0", "Opcode", base.HEX, opcodes_0_display)
local field_opcode_1 = ProtoField.uint8("matter.opcode1", "Opcode", base.HEX, opcodes_1_display)
local field_opcode_2 = ProtoField.uint8("matter.opcode2", "Opcode", base.HEX, opcodes_2_display)
local field_opcode_3 = ProtoField.uint8("matter.opcode3", "Opcode", base.HEX, opcodes_3_display)
local field_opcode_other = ProtoField.uint8("matter.opcodex", "Opcode", base.HEX)
	
-- Exchange ID
local field_exchange_id = ProtoField.uint16("matter.exchange_id", "Exchange ID", base.DEC)

-- Protocol ID
local field_protocol_id = ProtoField.uint16("matter.protocol_id", "Protocol ID", base.DEC, protocol_id_display)

-- Vendor ID
local field_vendor_id = ProtoField.uint16("matter.vendor_id", "Vendor ID", base.DEC)

-- Acknowledged Message Counter
local field_acknowledged_message_counter = ProtoField.uint32("matter.acknowledged_message_counter", "Acknowledged Message Counter", base.DEC)

-- Application payload
local field_security_extensions = ProtoField.bytes("matter.security_extensions", "Security Extensions")

-- Application payload
local field_application_payload = ProtoField.bytes("matter.application_payload", "Application Payload")

-- Attach all fields to the Matter protocol
proto_matter.fields = {
	field_message_flags, 
	field_message_flag_version,
	field_message_flag_source_node,
	field_message_flag_dsiz,
	field_session_id, 
	field_security_flags,
	field_security_flag_p,
	field_security_flag_c,
	field_security_flag_mx,
	field_security_flag_session_type,
	field_message_counter,
	field_source_node_id,
	field_destination_node_id_64,
	field_destination_node_id_16,
	field_message_payload,
	field_message_integrity,
	field_exchange_flags,
	field_opcode_0,
	field_opcode_1,
	field_opcode_2,
	field_opcode_3,
	field_exchange_flag_i,
	field_exchange_flag_a,
	field_exchange_flag_r,
	field_exchange_flag_sx,
	field_exchange_flag_v,
	field_exchange_id,
	field_protocol_id,
	field_vendor_id,
	field_acknowledged_message_counter,
	field_security_extensions,
	field_application_payload,
	generated_message_type,
	generated_debug_message,
	generated_tlv,
	generated_status_report
}

--- TLV Parser code ---

local tlv_element_types = {
	[00] = "Signed Integer, 1-octet value",
	[01] = "Signed Integer, 2-octet value",
	[02] = "Signed Integer, 4-octet value",
	[03] = "Signed Integer, 8-octet value",
	[04] = "Unsigned Integer, 1-octet value",
	[05] = "Unsigned Integer, 2-octet value",
	[06] = "Unsigned Integer, 4-octet value",
	[07] = "Unsigned Integer, 8-octet value",
	[08] = "Boolean False",
	[09] = "Boolean True",
	[10] = "Floating Point Number, 4-octet value",
	[11] = "Floating Point Number, 8-octet value",
	[12] = "UTF-8 String, 1-octet length",
	[13] = "UTF-8 String, 2-octet length",
	[14] = "UTF-8 String, 4-octet length",
	[15] = "UTF-8 String, 8-octet length",
	[16] = "Octet String, 1-octet length",
	[17] = "Octet String, 2-octet length",
	[18] = "Octet String, 4-octet length",
	[19] = "Octet String, 8-octet length",
	[20] = "Null",
	[21] = "Structure",
	[22] = "Array",
	[23] = "List",
	[24] = "End of Container",
	[25] = "Reserved",
	[26] = "Reserved",
	[27] = "Reserved",
	[28] = "Reserved",
	[29] = "Reserved",
	[30] = "Reserved",
	[31] = "Reserved"
}

local tlv_element_type_lengths = {
	[00] = 1,
	[01] = 2,
	[02] = 4,
	[03] = 8,
	[04] = 1,
	[05] = 2,
	[06] = 4,
	[07] = 8,
	[08] = 0,
	[09] = 0,
	[10] = 4,
	[11] = 8,
	[12] = -1,
	[13] = -1,
	[14] = -1,
	[15] = -1,
	[16] = -1,
	[17] = -1,
	[18] = -1,
	[19] = -1,
	[20] = 0,
	[21] = 0,
	[22] = 0,
	[23] = 0,
	[24] = 0,
	[25] = 0,
	[26] = 0,
	[27] = 0,
	[28] = 0,
	[29] = 0,
	[30] = 0,
	[31] = 0
}

local tlv_tag_controls = {
    ANONYMOUS = 0,
    CONTEXT_SPECIFIC = 1,
    COMMON_PROFILE_2 = 2,
    COMMON_PROFILE_4 = 3,
    IMPLICIT_PROFILE_2 = 4,
    IMPLICIT_PROFILE_4 = 5,
    FULLY_QUALIFIED_6 = 6,
    FULLY_QUALIFIED_8 = 7
}

local tlv_tag_controls_display = {
	[tlv_tag_controls.ANONYMOUS] = "Anonymous Tag Form, 0 octets",
	[tlv_tag_controls.CONTEXT_SPECIFIC] = "Context-specific Tag Form, 1 octet",
	[tlv_tag_controls.COMMON_PROFILE_2] = "Common Profile Tag Form, 2 octets",
	[tlv_tag_controls.COMMON_PROFILE_4] = "Common Profile Tag Form, 4 octets",
	[tlv_tag_controls.IMPLICIT_PROFILE_2] = "Implicit Profile Tag Form, 2 octets",
	[tlv_tag_controls.IMPLICIT_PROFILE_4] = "Implicit Profile Tag Form, 4 octets",
	[tlv_tag_controls.FULLY_QUALIFIED_6] = "Fully-qualified Tag Form, 6 octets",
	[tlv_tag_controls.FULLY_QUALIFIED_8] = "Fully-qualified Tag Form, 8 octets"
}

local tlv_tag_controls_length = {
	[tlv_tag_controls.ANONYMOUS] = 0,
	[tlv_tag_controls.CONTEXT_SPECIFIC] = 1,
	[tlv_tag_controls.COMMON_PROFILE_2] = 2,
	[tlv_tag_controls.COMMON_PROFILE_4] = 4,
	[tlv_tag_controls.IMPLICIT_PROFILE_2] = 2,
	[tlv_tag_controls.IMPLICIT_PROFILE_4] = 4,
	[tlv_tag_controls.FULLY_QUALIFIED_6] = 6,
	[tlv_tag_controls.FULLY_QUALIFIED_8] = 8
}

function tlv_length_length (element_type)
	if (element_type == 12 or element_type == 16) then
		return 1
	elseif (element_type == 13 or element_type == 17) then
		return 2
	elseif (element_type == 14 or element_type == 18) then
		return 3
	elseif (element_type == 15 or element_type == 19) then
		return 4
	else
		return 0
	end
end

-- Given a structure path starting with (protocol_id,opcode) and tag, map to display name or return nil
function tlv_label(path, tag_value)
	local map = tlv_label_map(path)
	if (map ~= nil) then
		return map[tag_value]
	end
	return nil
end	

function tlv_label_map(path)
	
	protocol_id_value = path[1]
	opcode_value = path[2]
	print("protocol_id_value=" .. protocol_id_value .. ", opcode_value=" .. opcode_value)
	local size = #path
	
	if (size == 2) then
		if (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.PBKDF_PARAM_REQ) then
			return {
				[1] = "Initiator Random",
				[2] = "Initiator Session ID",
				[3] = "Passcode ID",
				[4] = "Has PBKDF Parameters",
				[5] = "Initiator SEDParams"
			}
		elseif (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.PBKDF_PARAM_RESP) then
			return {
				[1] = "Initiator Random",
				[2] = "Responder Random",
				[3] = "responderSessionId",
				[4] = "pbkdf_parameters",
				[5] = "responderSEDParams"
			}
		elseif (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.PASE_PAKE1) then
			return {
				[1] = "pA"
			}
		elseif (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.PASE_PAKE2) then
			return {
				[1] = "pB",
				[2] = "cB"
			}
		elseif (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.PASE_PAKE3) then
			return {
				[1] = "cA"
			}
		end
	elseif (size == 3) then
		tag3 = path[3]
		if (protocol_id_value == protocol_id.SECURE_CHANNEL and (opcode_value == opcodes_0.PBKDF_PARAM_REQ or opcode_value == opcodes_0.PBKDF_PARAM_RESP)and tag3 == 5) then
			return {
				[1] = "sleepy-idle-interval",
				[2] = "sleepy-active-interval"
			}
		elseif (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.PBKDF_PARAM_RESP and tag3 == 4) then
			return {
				[1] = "iterations",
				[2] = "salt"
			}		
		end
		
	end
	return nil
end

-- Recursively loop through bytes to extract TLV elements and build subtrees
function tlv_parse (buffer, pos, tree, path)

	if (pos >= buffer:len()) then
		return pos
	end

	while (pos < buffer:len()) do
		-- Get element
		local start = pos
		
		-- Control
		local control = buffer(pos, 1):uint()
		local control_length = 1
		local element_type = bit.band(control, 0x1F)
		local tag_control = bit.rshift(bit.band(control, 0xE0), 5)

		pos = pos + control_length
		
		print("TAG CONTROL=" .. tag_control)
		-- Tag
		local tag_length = tlv_tag_controls_length[tag_control]
		local tag_value = nil
		if (tag_length > 0) then
			tag_value = buffer(pos, tag_length):le_uint()
		end
		pos = pos + tag_length
		
		-- Length
		local length_length = tlv_length_length(element_type);	
		local value_length = 0
		if (length_length > 0) then
			-- Variable length
			value_length = buffer(pos, length_length):le_uint()
		else
			-- Fixed for element type
			value_length = tlv_element_type_lengths[element_type]
		end
		
		if (length_length > 0) then
			print("length_length=" .. length_length .. ", ValueLength=" .. value_length .. ", length-buffer=" .. buffer(pos, length_length))
		end
		pos = pos + length_length
		
		-- value
		local value = nil
		local display = nil
		local container_start = false
		local container_end = false

		if (element_type == 0x00 or element_type == 0x01 or element_type == 0x02 or element_type == 0x03) then
			-- Signed Integer
			value = buffer(pos, value_length):le_int()

		elseif (element_type == 0x04 or element_type == 0x05 or element_type == 0x06 or element_type == 0x07) then
			-- Signed Integer
			value = buffer(pos, value_length):le_uint()

		elseif (element_type == 0x08) then
			-- Boolean False
			display = "False"
			
		elseif (element_type == 0x09) then
			-- Boolean True
			display = "True"
			
		elseif (element_type == 0x0A or element_type == 0x0B) then
			-- Float 4-octet / Float 8-octet

		elseif (element_type == 0x0C or element_type == 0x0D or element_type == 0x0E or element_type == 0x0F) then
			-- UTF-8 String X-octet
			if (value_length > 0) then
				value = buffer(pos, value_length):string()
			else
				value = "[EMPTY]"
			end

		elseif (element_type == 0x10 or element_type == 0x11 or element_type == 0x12 or element_type == 0x13) then
			-- Octet String X-octet
			if (value_length > 0) then
				value = buffer(pos, value_length)
			else
				value = "[EMPTY]"
			end
			
		elseif (element_type == 0x15) then
			container_start = true
			display = "{ Structure"
		elseif (element_type == 0x16) then
			container_start = true
			display = "{ Array"
		elseif (element_type == 0x17) then
			container_start = true
			display = "{ List"
		elseif (element_type == 0x18) then
			container_end = true
			display = "} End"
		end	
		pos = pos + value_length
		
		local tag_str = nil
		if (tag_value ~= nil) then
			tag_str = tlv_label(path, tag_value)
			if (tag_str == nil) then
				tag_str = tag_value
			end
		end
				
		-- Overview text
		local summary
		local str
		if (display ~= nil) then
			str = display
		elseif (value ~= nil) then
			str = value
		else
			str = tlv_element_types[element_type]
		end
		if (tag_str ~= nil) then
			summary =  tag_str .. "=" .. str
		else 
			summary =  str
		end

		-- Subtree details
		local subtree = tree:add(generated_tlv, buffer(start, pos - start), summary)

		subtree:add(generated_tlv, buffer(start, control_length), "element_type=" .. tlv_element_types[element_type] .. ", tag_control=" .. tlv_tag_controls_display[tag_control])
		if (tag_length > 0) then
			subtree:add(generated_tlv, buffer(start + control_length, tag_length), "tag=" .. tag_value)
		end
		if (length_length > 0) then
			subtree:add(generated_tlv, buffer(start + control_length + tag_length, length_length), "length=" .. value_length)
		end
		if (value_length > 0) then
			subtree:add(generated_tlv, buffer(start + control_length + tag_length + length_length, value_length), "value=" .. value)
		elseif (value ~= nil) then
			subtree:add(generated_tlv, "value=" .. value)	
		end
		--	print("element_type=" .. element_types[element_type] .. ", tag_control=" .. tag_controls[tag_control])

		-- next element
		if (pos <= start) then
			-- No data parsed? Bail.
			return pos
		end
		
		if (container_end) then
			-- End of this call
			return pos
		end
		
		if (container_start) then
			-- Recurse!
			if (tag_value ~= nil) then
				table.insert(path, tag_value)
			end			
			pos = tlv_parse(buffer, pos, subtree, path)		
		end

	end
	
end

--- Status Report parsing ---

local status_report_codes = {
	[0] = "SUCCESS",
	[1] = "FAILURE",
	[2] = "BAD_PRECONDITION",
	[3] = "OUT_OF_RANGE",
	[4] = "BAD_REQUEST",
	[5] = "UNSUPPORTED",
	[6] = "UNEXPECTED",
	[7] = "RESOURCE_EXHAUSTED",
	[8] = "BUSY",
	[9] = "TIMEOUT",
	[10] = "CONTINUE",
	[11] = "ABORTED",
	[12] = "INVALID_ARGUMENT",
	[13] = "NOT_FOUND",
	[14] = "ALREADY_EXISTS",
	[15] = "PERMISSION_DENIED",
	[16] = "DATA_LOSS"
}

function status_report_parse (buffer, tree)

	local general_code = buffer(0, 2):le_uint()
	tree:add(generated_status_report, buffer, "general_code=" .. status_report_codes[general_code])
	
end


-- Dissector
function proto_matter.dissector(buffer, pinfo, tree)

	-- print("Buffer length = " .. buffer:len())
	
    -- Protocol display name 
    pinfo.cols.protocol = "Matter"
	
    -- The entire UDP payload is Matter protocol data
    local payload_tree = tree:add( proto_matter, buffer() )

	-- Matter message format
	-- --------------------------------------------------------|
	-- |  LENGTH     |         FIELD         | COMMENT         |
	-- --------------------------------------------------------|
	-- | 2 bytes     |    [Message Length]   | N/A for UDP     |
	-- | 1 bytes     |    Message Flags      |                 |
	-- | 2 bytes     |    Session ID         |                 |
	-- | 1 bytes     |    Security Flags     |                 |
	-- | 4 bytes     |    Message Counter    |                 |
	-- | 0/8 bytes   |    [Source Node ID]   |                 |
	-- | 0/2/8 bytes | [Destination Node ID] |                 |
	-- |  variable   |  [Message extensions] |                 |
	-- |  variable   |  [Message Payload]    |                 |
	-- |  variable   |  [Message Integrity]  |                 | 
	-- ------------------------------------------------------- |
	
	-- Message Flags 	
    local message_flags_pos = 0
    local message_flags_len = 1
    local message_flags_buffer = buffer(message_flags_pos,message_flags_len)
    local message_flags_subtree = payload_tree:add(field_message_flags, message_flags_buffer)
	
	-- Message Flag bit masks (these are applied in field declaration and all reference the same byte)
	-- --------------------------
	-- | 7 6 5 4 | 3 | 2 | 1 0  |
	-- --------------------------
	-- | Version | - | S | DSIZ |
	-- --------------------------
	message_flags_subtree:add(field_message_flag_version, message_flags_buffer)
	message_flags_subtree:add(field_message_flag_source_node, message_flags_buffer)
	message_flags_subtree:add(field_message_flag_dsiz, message_flags_buffer)
	
	local destination_node_64_exists = (bit.band(message_flags_buffer(0,1):uint(), 0x03) == 0x01)
	local destination_node_16_exists = (bit.band(message_flags_buffer(0,1):uint(), 0x03) == 0x02)

	-- Very clunky way of extracting boolean value... does the job.
	local source_node_exists = (bit.band(message_flags_buffer(0,1):uint(), 0x04) > 0)

	-- Session ID. 'add_le' signifies little endian
    local session_id_pos = message_flags_pos + message_flags_len
    local session_id_len = 2
    local session_id_buffer = buffer(session_id_pos, session_id_len)
	local session_id_exists = session_id_buffer(0,session_id_len):uint() > 0

    payload_tree:add_le(field_session_id, session_id_buffer)

	-- Security Flags
    local security_flags_pos = session_id_pos + session_id_len
    local security_flags_len = 1
    local security_flags_buffer = buffer(security_flags_pos,security_flags_len)
    local security_flags_subtree = payload_tree:add(field_security_flags, security_flags_buffer)

	-- Security Flag bit masks (these are applied in field declaration and all reference the same byte)
	-- ----------------------------------------
	-- | 7 | 6 | 5  | 4 | 3 | 2 |   1  |  0   |
	-- ---------------------------------------|
	-- | P | C | MX | Reserved  | SessionType |
	-- ----------------------------------------
	security_flags_subtree:add(field_security_flag_p, security_flags_buffer)
	security_flags_subtree:add(field_security_flag_c, security_flags_buffer)
	security_flags_subtree:add(field_security_flag_mx, security_flags_buffer)
	security_flags_subtree:add(field_security_flag_session_type, security_flags_buffer)

	local session_type_unicast = (bit.band(security_flags_buffer(0,1):uint(), 0x03) == 0x00)

	-- Message Counter. 'add_le' signifies little endian message counter!
    local message_counter_pos = security_flags_pos + security_flags_len
    local message_counter_len = 4
    local message_counter_buffer = buffer(message_counter_pos,message_counter_len)
    payload_tree:add_le(field_message_counter, message_counter_buffer)

	-- Source node. 'add_le' = little endian. Optional depending on message flag 'S'.
	local source_node_id_pos = message_counter_pos + message_counter_len
	local source_node_id_len = 0
	if (source_node_exists)
	then		
		source_node_id_len = 8
		local source_node_id_buffer = buffer(source_node_id_pos, source_node_id_len)
		payload_tree:add_le(field_source_node_id, source_node_id_buffer)
	end

	-- Destination node. Optional depending on message flag 'dsiz'.
	local destination_node_id_pos = source_node_id_pos + source_node_id_len
	local destination_node_id_len = 0
	if (destination_node_64_exists)
	then		
		destination_node_id_len = 8
		local destination_node_id_buffer = buffer(destination_node_id_pos, destination_node_id_len)
		payload_tree:add_le(field_destination_node_id_64, destination_node_id_buffer)
	elseif (destination_node_16_exists)
	then
		destination_node_id_len = 2
		local destination_node_id_buffer = buffer(destination_node_id_pos, destination_node_id_len)
		payload_tree:add_le(field_destination_node_id_16, destination_node_id_buffer)
	end

	-- Message payload
	local message_payload_pos = destination_node_id_pos + destination_node_id_len
	local message_payload_buffer = buffer(message_payload_pos)
	local message_payload_subtree = payload_tree:add(field_message_payload, message_payload_buffer)
	
	-- Unsecured session when Session Type and Session ID are set to 0
	-- No encryption, privacy, or message integrity
	local unsecured_session = session_type_unicast and not session_id_exists
	local encryption_disabled = true
	if (unsecured_session or encryption_disabled)
	then
		-- Display encryption status: No Encryption
		if (unsecured_session)
		then
			message_payload_subtree:add(generated_message_type, "No Encryption"):set_generated()
		else
			message_payload_subtree:add(generated_message_type, "Encryption Disabled?!"):set_generated()
		end
		
		-- Exchange Flags
		local exchange_flags_pos = message_payload_pos
		local exchange_flags_len = 1
		local exchange_flags_buffer = buffer(exchange_flags_pos, exchange_flags_len)
		local exchange_flags_subtree = message_payload_subtree:add(field_exchange_flags, exchange_flags_buffer)

		-- Exchange Flag bit masks 
		-- ----------------------------------
		-- | 7 | 6 | 5 | 4 | 3  | 2 | 1 | 0 |
		-- ---------------------------------|
		-- | - | - | - | V | SX | R | A | I |
		-- ----------------------------------
		exchange_flags_subtree:add(field_exchange_flag_i, exchange_flags_buffer)
		exchange_flags_subtree:add(field_exchange_flag_a, exchange_flags_buffer)
		exchange_flags_subtree:add(field_exchange_flag_r, exchange_flags_buffer)
		exchange_flags_subtree:add(field_exchange_flag_sx, exchange_flags_buffer)
		exchange_flags_subtree:add(field_exchange_flag_v, exchange_flags_buffer)		

		local vendor_id_exists = (bit.band(exchange_flags_buffer(0,1):uint(), 0x10) > 0)
		local acknowledged_message_counter_exists = (bit.band(exchange_flags_buffer(0,1):uint(), 0x02) > 0)
		local secured_extensions_exists = (bit.band(exchange_flags_buffer(0,1):uint(), 0x08) > 0)


		-- Opcode
		local opcode_pos = exchange_flags_pos + exchange_flags_len
		local opcode_len = 1
		local opcode_buffer = buffer(opcode_pos, opcode_len)
		--local opcode_subtree = message_payload_subtree:add(field_opcode_0, opcode_buffer)
		
		-- Exchange ID
		local exchange_id_pos = opcode_pos + opcode_len
		local exchange_id_len = 2
		local exchange_id_buffer = buffer(exchange_id_pos, exchange_id_len)
		message_payload_subtree:add_le(field_exchange_id, exchange_id_buffer)

		-- Protocol ID
		local protocol_id_pos = exchange_id_pos + exchange_id_len
		local protocol_id_len = 2
		local protocol_id_buffer = buffer(protocol_id_pos, protocol_id_len)
		message_payload_subtree:add_le(field_protocol_id, protocol_id_buffer)
		
		local protocol_id_value = protocol_id_buffer(0,1):uint()
		if (protocol_id_value == protocol_id.SECURE_CHANNEL) then
			message_payload_subtree:add(field_opcode_0, opcode_buffer)
		elseif (protocol_id_value == protocol_id.INTERACTION_MODEL) then
			message_payload_subtree:add(field_opcode_1, opcode_buffer)
		elseif (protocol_id_value == protocol_id.INTERACTION_MODEL) then
			message_payload_subtree:add(field_opcode_2, opcode_buffer)
		elseif (protocol_id_value == protocol_id.BDX) then
			message_payload_subtree:add(field_opcode_3, opcode_buffer)
		elseif (protocol_id_value == protocol_id.IDENTIFICATION_DECLARATION) then
			message_payload_subtree:add(field_opcode_other, opcode_buffer)
		end

		-- Vendor ID
		local vendor_id_pos = protocol_id_pos + protocol_id_len
		local vendor_id_len = 0
		if (vendor_id_exists)
		then
			vendor_id_len = 2
			local vendor_id_buffer = buffer(vendor_id_pos, vendor_id_len)
			message_payload_subtree:add_le(field_vendor_id, vendor_id_buffer)
		end

		-- Acknowledged Message Counter
		local acknowledged_message_counter_pos = vendor_id_pos + vendor_id_len
		local acknowledged_message_counter_len = 0
		if (acknowledged_message_counter_exists)
		then
			acknowledged_message_counter_len = 4
			local acknowledged_message_counter_buffer = buffer(acknowledged_message_counter_pos, acknowledged_message_counter_len)
			message_payload_subtree:add_le(field_acknowledged_message_counter, acknowledged_message_counter_buffer)
		end
		
		-- Secured Extensions
		-- Unused version 1.0. Reserved for future use
		
		local opcode_value = opcode_buffer(0,1):uint()
		if (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.MRP_STANDALONE_ACK) then
			-- Standalone Acknowledgement: no payload
		else
			-- Application payload
			local application_payload_pos = acknowledged_message_counter_pos + acknowledged_message_counter_len
			local application_payload_buffer = buffer(application_payload_pos)
			local application_payload_subtree = message_payload_subtree:add(field_application_payload, application_payload_buffer)

			if (protocol_id_value == protocol_id.SECURE_CHANNEL and opcode_value == opcodes_0.STATUS_REPORT) then
				-- Status report. 'Appendix D' of the Matter Core specification
				status_report_parse(application_payload_buffer, application_payload_subtree)
			else 				
				-- Assume everything else is TLV. May not be true.
				-- TLV: See 'Appendix A' of the Matter Core specification
				tlv_parse(application_payload_buffer, 0, application_payload_subtree, {protocol_id_value, opcode_value})
			end
		end
		
	else
		-- Display encryption status: Encrypted
		message_payload_subtree:add(generated_message_type, "Encrypted"):set_generated()        	
		
		-- Message Integrity (TODO: Fixed size, last 16 bytes!)
		payload_tree:add(field_message_integrity, 0)

	end

end

-- register Matter protocol on UDP port 5540
udp_table = DissectorTable.get("udp.port"):add(5540, proto_matter)
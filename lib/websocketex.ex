defmodule Websocketex do
	use Agent
	require Record
	require Bitwise
	@websocket_version 13
	@timeout 20
	@opcodes %{continuation: 0x0, text: 0x1, binary: 0x2, connection_close: 0x8, ping: 0x9, pong: 0xA}
	@status_codes %{normal_closure: 1000, going_away: 1001, protocol_error: 1002, invalid_data: 1003, no_code: 1005, abnormal_close: 1006, non_utf8: 1007, policy_violation: 1008, large_message: 1009, missing_extension: 1010, unexpected_condition: 1011, tls_failed: 1015}
	@frame_max_size_bytes 1500
	@frame_max_size_bits @frame_max_size_bytes * 8
	@message_max_byte_size 256000 # 256KB
	@pending_connections 10

  @moduledoc """
  This module implements RFC6455, better known as the WebSocket Protocol.
  """
	defp process_request(socket, headers) do
		case recvTcp(socket, 0) do
			# Get protocol, method and uri
			{:ok, {:http_request, :GET, {path, query}, {1,1}}} ->  process_request(socket, %Websocketex.Headers{headers | path: path, query: query})
			# Process headers
			# Required websocket headers
			# Example: {:ok, {:http_header, 24, :"User-Agent", :undefined, "curl/7.35.0"}}
			{:ok, {:http_header, _size, :Host, _otherfield, host}} -> process_request(socket, %Websocketex.Headers{headers | host: host})
			{:ok, {:http_header, _size, :Upgrade, _otherfield, websocket}} -> process_request(socket, %Websocketex.Headers{headers | upgrade: websocket})
			{:ok, {:http_header, _size, :Connection, _otherfield, upgrade}} -> process_request(socket, %Websocketex.Headers{headers | connection: upgrade})
			{:ok, {:http_header, _size, "Sec-Websocket-Key", _otherfield, sec_websocket_key}} -> process_request(socket, %Websocketex.Headers{headers | sec_websocket_key: sec_websocket_key})
			{:ok, {:http_header, _size, "Sec-Websocket-Version", _otherfield, version}} -> process_request(socket, %Websocketex.Headers{headers | sec_websocket_version: version})
			# Optional headers
			{:ok, {:http_header, _size, "Origin", _otherfield, origin}} -> process_request(socket, %Websocketex.Headers{headers | origin: origin})
			{:ok, {:http_header, _size, "Sec-Websocket-Protocol", _otherfield, protocol}} -> process_request(socket, %Websocketex.Headers{headers | sec_websocket_protocol: protocol})
			{:ok, {:http_header, _size, "Sec-Websocket-Extensions", _otherfield, extensions}} -> process_request(socket, %Websocketex.Headers{headers | sec_websocket_extensions: extensions})
			# Other headers
			{:ok, {:http_header, _size, header_field, _otherfield, value}} ->
				%Websocketex.Headers{rest_of_headers: rest_of_headers} = headers
				new_rest = rest_of_headers ++ [{header_field, value}]
				process_request(socket, %Websocketex.Headers{headers | rest_of_headers: new_rest})
			# If an error occurs receiving
			{:error, reason} -> {:error, reason}
			# If there is no matching case
			:error -> sendTcp(socket, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			# Other procotol version, must thorw error
			{:ok, {:http_request, _method, {:abs_path, _path}, {1,0}}} -> sendTcp(socket, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			# End of Headers
			{:ok, :http_eoh} -> {:ok, socket, headers}
			# SSL request on non SSL server socket
			{:ok, {:http_error, _binary}} ->
				# Refuse, close connection on client
				sendTcp(socket, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
				# Exception
				{:error, "Protocol error. Cannot connect to non SSL/TLS socket."}
		end
	end
	# Send the servers handshake response
	# TODO: Handle protocols and extensions properly
	# Client sends a list of protocols and the server must choose one, that it implements and return it
	defp send_handshake_response(socket, headers) do
		if headers.sec_websocket_version == nil do
			sendTcp(socket, "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: " <> Integer.to_string(@websocket_version) <> "\r\n\r\n")
		else
			if String.to_integer(headers.sec_websocket_version) != @websocket_version do
				sendTcp(socket, "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: " <> Integer.to_string(@websocket_version) <> "\r\n\r\n")
			else
				# Server options the developer set
				%Websocketex.ServerOptions{extensions: extensions, origins: origins, protocols: protocols} = get_agent()
				case check_origin(origins, headers.origin) do
					true ->
						# String defined in RFC 6455 to concatinate with Sec-Websocket-key
						accept_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
						# Concatinate the key in the headers with the accept string,  hash that with SHA-1 and finally base64 encode it.
						sec_websocket_accept = Base.encode64(:crypto.hash(:sha, headers.sec_websocket_key <> accept_string))
						# Send handshake
						sendTcp(socket, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
							<> sec_websocket_accept
							<> if protocols do "Sec-WebSocket-Protocol: " <> Enum.join(protocols, ",") <> "\r\n" else "" end
							<> if extensions do "Sec-WebSocket-Extensions: " <> Enum.join(extensions, ";") <> "\r\n" else "" end
							<> "\r\n\r\n")
						# After handshake you must change server opts in order to receive data.
						if is_ssl?(socket) do
							:ssl.setopts(socket, [{:packet, 0}])
						else
							:inet.setopts(socket, [{:packet, 0}])
						end

					false -> sendTcp(socket, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
				end
			end
		end

	end

	defp check_origin(origins, origin) do
		# If allowed origins doesn't contain all (*)
		if !Enum.member?(origins, "*") do
			# If supplied origin header is null send 403 error code
			if !origin do
				false
			else
			# If supplied header is not null then check if it's in the whitelist, if not send 403 error
				if !Enum.member?(origins, origin) do
					false
				else
					true
				end
			end
		else
			true # All good
		end
	end

	defp start_agent(options) do

		pid = Process.whereis(__MODULE__)

		if pid == nil do
			Agent.start_link(fn -> options end, name: __MODULE__)
		else
			if Process.alive?(pid) do
				stop_agent()
				Agent.start_link(fn -> options end, name: __MODULE__)
			end
		end

	end

	defp save_agent(key, value) do
		Agent.update(__MODULE__, fn state -> Map.put(state, String.to_existing_atom(key), value) end)
	end

	defp get_agent() do
		Agent.get(__MODULE__, fn state -> state end)
	end

	defp stop_agent() do
		Agent.stop(__MODULE__, :normal)
	end
	@doc """
	Closes a WebSocket. Can only be used by the server.
	# Parameters
	* WebSocket

	## Examples
				iex> {:ok, connectedWebsocket} = Websocketex.listen(5678) |> Websocketex.accept
				iex> Websocketex.close(connectedWebsocket)
	"""
	def close(websocket) do
		if is_context?(:server) do
			{:ok, code} = get_status_code(:normal_closure)
			Websocketex.send(websocket, code, :connection_close)
			clean_closure(websocket)
		else
			{:error, "Client cannot close WebSocket connection."}
		end
	end

	defp close(socket, status_code_type) do
		{:ok, code} = get_status_code(status_code_type)
		Websocketex.send(socket, code, :connection_close)
		clean_closure(socket)
	end

	defp clean_closure(socket) do
		if is_context?(:server) do
			shutdown(socket, :read_write)
			closeTcp(socket)
		else
			# Waiting for server close response when client initiates close
			case recvTcp(socket, 2) do
				# Close with no bin data received
				{:ok, 0} ->
					shutdown(socket, :read_write)
					closeTcp(socket)
				# Close with bin data received
				{:ok, <<data::binary>>} ->
					data = handle_frame({:ok, data}, socket)
					shutdown(socket, :read_write)
					closeTcp(socket)
					data
				{:error, reason} -> {:error, reason}
			end
		end
	end

	defp closeTcp(socket) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.close(socket)
		else
			:gen_tcp.close(socket)
		end
	end
	@doc """
	Listens to a given port and takes server options
	## Parameters
	* port
	* server_options - %Websocketex.ServerOptions struct

	Note:
		These configurations will always be present in socket: [:binary, {:packet, :http_bin}, {:active, false}]

	## Examples
				iex> websocket = Websocketex.listen(5678)
	"""
	def listen(port, server_options \\ %Websocketex.ServerOptions{}) do
		# Will add these socket default options
		%Websocketex.ServerOptions{socket_options: socket_options} = server_options
		socket_options = Enum.concat(socket_options, [:binary, {:packet, :http_bin}, {:active, false}])
		# If the server is configured as an ssl
		if server_options.ssl do
			:ssl.start()
			# Started ssl, check to see if I have the minimum required files for SSL connection
			case Websocketex.ServerOptions.is_ssl_ready?(server_options) do
				true ->
					# Add ssl files to server options
					%Websocketex.ServerOptions{caCertificate: ca, certificate: cert, key: key} = server_options
					if is_nil(ca) do
						socket_options = Enum.concat(socket_options, [{:certfile, cert}, {:keyfile, key}])
					else
						socket_options = Enum.concat(socket_options, [{:cacertfile, ca}, {:certfile, cert}, {:keyfile, key}])
					end
					case :ssl.listen(port, socket_options) do
						{:ok, sslSocket} ->
							start_agent(server_options) # save the options
							sslSocket
						{:error, reason} -> {:error, reason}
					end
				false ->
					{:error, "Missing Certificate or Key file."}
			end
		else # plain old TCP sockets
			case :gen_tcp.listen(port, socket_options) do
				{:ok, listenSocket} ->
						# Save server options into an Agent, so the process state can be accesed throughout functions
						start_agent(server_options)
						listenSocket
				{:error, reason} -> {:error, reason}
			end
		end
	end

	defp accept_helper(socket) do
		case process_request(socket, %Websocketex.Headers{}) do
			{:ok, socket, headers} ->
				# Check if http headers are valid
				if !Websocketex.Headers.check_server_headers(headers) do
					sendTcp(socket, "HTTP/1.1 400 Bad Request\r\nConnection: closed\r\n\r\n")
				end
				# Try to send the handshake
				case send_handshake_response(socket, headers) do
					:ok -> {:ok, socket}
					{:error, reason} ->
						sendTcp(socket, "HTTP/1.1 400 Bad Request\r\nConnection: closed\r\n\r\n")
						{:error, reason}
				end
			{:error, reason} -> {:error, reason}
		end
	end
	@doc """
	Accepts an incoming WebSocket connection request
	## Parameters
	* listeningSocket

	## Examples
				iex> {:ok, connectedWebsocket} = Websocketex.listen(5678) |> Websocketex.accept

	"""
	def accept(socket) do
		# acceptTcp() determines if the socket is ssl socket or not and uses the appropriate code
		case acceptTcp(socket) do
			{:ok, socket} ->
					accept_helper(socket)
			{:error, _reason} ->
				sendTcp(socket, "HTTP/1.1 403 Forbidden\r\nConnection: closed\r\n\r\n")
				# Send error back up
				{:error, "SSL/TLS handshake timedout."}
		end
	end

	# Call for getting the payload data
	defp handle_frame(packet, socket) do
		# Send -1 opcode which will only be replaced with the actual opcode when a fragmentation occurs
		handle_frame(packet, socket, <<>>, -1)
	end

	# Returns the payload data accumulated
	defp handle_frame(packet, socket, acc, frag_opcode) do
			case packet do
				{:ok, frame} ->
					<<fin::size(1), _rsv1::size(1), _rsv2::size(1), _rsv3::size(1), opcode::size(4), mask::size(1), payload_length::size(7)>> = frame
					# If mask is 0, then you must terminate. All client packets must be masked.
					# In server context only
					if mask == 0 and is_context?(:server) do
						close(socket, :protocol_error)
					else
						if mask == 1 and is_context?(:client) do
							close(socket, :protocol_error)
						else
							payload_data_length = check_payload_length(payload_length, socket)
							# Check if the frame has a mask
							masking_key = cond do
								mask == 1 ->
									# Get the next 4 byes of the masking key
									case recvTcp(socket, 4) do
										{:ok, masking_key} ->
											masking_key
									end
								mask == 0 ->
									0
								true -> 0
							end
							# Now get the data in the frame
							case recvTcp(socket, payload_data_length) do
								{:ok, rest} ->
									cond do
										# Close connection, message to large
										bit_size(rest) > @message_max_byte_size ->
											close(socket, :large_message)
										# Fragmentation starts
										# Send the opcode in the function call
										fin == 0 and opcode != 0 ->
											# Concat the fragmented data
											acc = <<acc::binary, rest::binary>>
											# Get the next fragment
											recvTcp(socket, 2)
											|>
											handle_frame(socket, acc, opcode)
										# Not the last frame and a control frame
										fin == 0 and opcode >= 0x8 ->
											if is_context?(:client) do
												data = rest
											else # Server context
												data = unmask_data(masking_key, rest)
											end
											handle_control_frames(opcode, socket, data)
											# Get the next fragment
											recvTcp(socket, 2)
											|>
											handle_frame(socket, acc, frag_opcode)
										# Whole bunch of fragmented frames
										fin == 0 and opcode == 0 ->
											# Concat the fragmented data
											acc = <<acc::binary, rest::binary>>
											# Get the next fragment
											recvTcp(socket, 2)
											|>
											handle_frame(socket, acc, frag_opcode)
										#The end of fragments. Return data.
										fin == 1 and opcode == 0 ->
											# Concat data and return
											acc = <<acc::binary, rest::binary>>
											# Return the data
											if is_context?(:client) do
												data = acc
											else
												data = unmask_data(masking_key, acc)
											end
											# Check if data is valid UTF-8 if it's text
											validate_data(frag_opcode, data, socket)
										# An unfragmented frame came in
										fin == 1 and (opcode == 0x1 or opcode == 0x2)->
											# Concat data and return
											acc = <<acc::binary, rest::binary>>
											if is_context?(:client) do
												data = acc
											else
												data = unmask_data(masking_key, acc)
											end
											# Check if data is valid UTF-8 if it's text
											validate_data(opcode, data, socket)
										# An unfragmented frame with a control code
										fin == 1 and opcode >= 0x8 ->
											if is_context?(:client) do
												data = rest
											else
												data = unmask_data(masking_key, rest)
											end
											handle_control_frames(opcode, socket, data)
									end


								{:error, reason} -> {:error, reason}
							end # End of case recv
						end # else > else
					end #end of masking validation

				{:error, reason} -> {:error, reason}
			end
	end

	# Check if data is valid UTF-8 if it's text
	defp validate_data(opcode, data, socket) do
		cond do
			opcode_is?(opcode, :text) ->
				# check for valid UTF-8
				if String.valid?(data) do
					data
				else
					# Not valid UTF-8, send protocl error
					close(socket, :non_utf8)
				end
			opcode_is?(opcode, :binary) ->
				if is_binary(data) do
					data
				else
					close(socket, :invalid_data)
				end
			true ->
				close(socket, :protocol_error)
		end
	end

	# Determines which type of control frame is received, if any, and processes them accordingly
	defp handle_control_frames(opcode, socket, data) do
		cond do
			opcode_is?(opcode, :connection_close) ->
				case get_status_code(:policy_violation) do
					{:ok, code} ->
						Websocketex.send(socket, code, :connection_close)
					:error -> raise "Protocol error. Invalid status code."
				end
			# Ping, send pong
			opcode_is?(opcode, :ping) ->
				Websocketex.send(socket, data, :pong)
			# Pong, do nothing
			opcode_is?(opcode, :pong) ->
				true
		end
	end

	# Unmask the data
	defp unmask_data(masking_key, data) do
		unmask_data(masking_key, data, <<>>)
	end

	# Reads data in 32 bit chunks, to take advantage of the key's size, until the data left is less than 32 bits. Then it uses the data bit size to XOR with the key.
	defp unmask_data(masking_key, data, acc) do
		if is_integer(data) do
			data_size = bit_size(:binary.encode_unsigned(data)) # Data size in bits
		else
			data_size = bit_size(data) # Data size in bits
		end
		if data_size >= 32 do # If the remaining data is > 32
			if is_integer(data) do
				<<datagram::size(32)>> = :binary.encode_unsigned(data)
			else
				<<datagram::size(32), rest_data::binary >>  = data
			end
			<<keygram::size(32), _rest_key::binary>> = masking_key
			key = keygram
			unmask_data(masking_key, rest_data, <<acc::binary, Bitwise.bxor(key, datagram)::size(32)>>)
		else
				if data_size > 0 do
					if is_integer(data) do
						<<datagram::size(data_size), rest_data::binary>>  = :binary.encode_unsigned(data)
					else
						<<datagram::size(data_size), rest_data::binary >>  = data
					end
					<<keygram::size(data_size), _rest_key::binary>> = masking_key
					key = keygram
					unmask_data(masking_key, rest_data, <<acc::binary, Bitwise.bxor(key, datagram)::size(data_size)>>)
				else # When the data left is 0 return the Payload Data data
					acc
				end
		end

	end
	# Masks the data. The operation is the same as unmasking the data so let's call it
	defp mask_data(masking_key, data) do
		unmask_data(masking_key, data, <<>>)
	end

	# Returns the payload data length in bytes
	defp check_payload_length(payload_length, socket) do
		cond do
			payload_length <= 125 ->
				payload_length

			payload_length == 126 ->
				case recvTcp(socket, 2) do # 16 bits
					{:ok, length} ->
						length
					{:error, reason} -> {:error, reason}
				end
			payload_length == 127 ->
				case recvTcp(socket, 8) do # 64 bits
					{:ok, length} ->
						length
					{:error, reason} -> {:error, reason}
				end
		end
	end

	# Handles all incoming data from clients and servers
	@doc """
	Receives data from a WebSocket
	## Parameters
	* WebSocket

	## Examples
				iex> {:ok, connectedWebsocket} = Websocketex.listen(5678) |> Websocketex.accept
				iex> Websocketex.recv(connectedWebsocket)

	"""
	def recv(socket) do
		# Get the first 2 bytes or 16 bits of the frame
		recvTcp(socket, 2)
		|> handle_frame(socket)
	end

	defp shutdown(socket, how) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.shutdown(socket, how)
		else
			:gen_tcp.shutdown(socket, how)
		end
	end
	@doc """
	Connects to a WebSocket server
	## Parameters
	* Protocol - :ws or :wss
	* Address - localhost or 192.168.1.1 or domain.com
	* Port - 1234
	* Path - chat/connected
	* Query - ?var1=45
	* Options - %Websocketex.ClientOptions - Struct
	* timeout - Number of seconds in milliseconds

	Note:
		These configurations will always be present in socket: [:binary, {:active, false}]]

	## Examples
				iex> {:ok, websocket} = Websocketex.connect(:ws, 'localhost', 5678)
	"""
	def connect(protocol, address) do
		connect(protocol, address, %Websocketex.ClientOptions{})
	end

	def connect(protocol, address, port \\ 0, path \\ "", query \\ "", options \\ %Websocketex.ClientOptions{}, timeout \\ :infinity) do
		connectTcp(protocol, address, port, path, query, options, timeout)
	end

	# TODO: Serialize multiple connect's, there can only be one CONNECTING at a time
	defp connectTcp(protocol, address, port, path, query, options, timeout) do
		# Add path and query to address
		if String.valid?(path) and path != "" do
			address = to_charlist(to_string(address) <> "/" <> path)
		end
		if String.valid?(query) and query != "" do
			address = to_charlist(to_string(address) <> "?" <> query)
		end
		cond do
			protocol == :ws ->
				# Default port
				if port == 0 do
					port = 80
				end
				%Websocketex.ClientOptions{socket_options: socket_options} = options
				socket_options = Enum.concat(socket_options, [:binary, {:active, false}])
				case :gen_tcp.connect(address, port, socket_options, timeout) do
					{:ok, socket} ->
						options = %Websocketex.ClientOptions{options | path: path, socket_options: socket_options}
						start_agent(options)
						case send_handshake_request(socket, options) do
							:ok ->
								{:ok, socket}
							{:error, reason} -> {:error, reason}
						end
					{:error, reason} -> {:error, reason}
				end
			protocol == :wss ->
				:ssl.start()
				# Default port
				if port == 0 do
					port = 443
				end
				%Websocketex.ClientOptions{socket_options: socket_options} = options
				socket_options = Enum.concat(socket_options, [:binary, {:active, false}])
				case :ssl.connect(address, port, socket_options, timeout) do
					{:ok, sslSocket} ->
						options = %Websocketex.ClientOptions{options | path: path, ssl: true, socket_options: socket_options}
						start_agent(options)
						case send_handshake_request(sslSocket, options) do
							:ok ->
								{:ok, sslSocket}
							{:error, reason} -> {:error, reason}
						end
					{:error, reason} -> {:error, reason}
				end
			true ->
				raise "Error unsoported protocol."
		end
	end
	# Send a clients handshake request
	# TODO: Manage the rest of the header a client may specify
	defp send_handshake_request(socket, options) do
		# From the handshake
		%Websocketex.ClientOptions{origin: origin, protocols: protocols, extensions: extensions} = options
		{:ok, host} = :inet.gethostname()
		key = Base.encode64(:crypto.strong_rand_bytes(16))
		upgrade_request = "GET " <> "/" <> " HTTP/1.1"
		<> if origin != nil do "\r\nOrigin: http://" <> origin else "" end
		<>"\r\nHost: " <> to_string(host)
		<>"\r\nUpgrade: websocket\r\nConnection: Upgrade"
		<> "\r\nSec-WebSocket-Key: " <> key
		<> "\r\nSec-WebSocket-Version: " <> Integer.to_string(@websocket_version)
		<> if protocols do "Sec-WebSocket-Protocol: " <> Enum.join(protocols, ",") <> "\r\n" else "" end
		<> if extensions do "Sec-WebSocket-Extensions: " <> Enum.join(extensions, ";") <> "\r\n" else "" end
		<> "\r\n\r\n"
		# Send the handshake request to server
		case sendTcp(socket, upgrade_request) do
			:ok ->
				# Change socket to receive http packets
				if is_ssl?(socket) do
					:ssl.setopts(socket, [{:packet, :http_bin}])
				else
					:inet.setopts(socket, [{:packet, :http_bin}])
				end
				# Handshake sent
				# Get the response from the server
				# Server respondend to handshake
				case process_server_handshake_response(socket, %Websocketex.Headers{}) do
					{:ok, headers} ->
						validate_handshake_response_headers(socket, headers, key, protocols, extensions)
					{:ok, port, headers}->
						validate_handshake_response_headers(socket, headers, key, protocols, extensions)
					{:error, reason} -> {:error, reason}
				end
			{:error, reason} -> {:error, reason}
		end
	end

	defp validate_handshake_response_headers(socket, headers, key, protocols, extensions) do
		%Websocketex.Headers{sec_websocket_protocol: server_protocol, sec_websocket_extensions: server_extensions} = headers
		if Websocketex.Headers.check_client_headers(headers, key) and Websocketex.ClientOptions.check_protocol(protocols, server_protocol) and Websocketex.ClientOptions.check_extensions(extensions, server_extensions) do
			# handshake ok
			:ok
		else
			#Failed
			close(socket, :abnormal_close)
			{:error, "Protocol error. Malformed handshake. Closing abnormally."}
		end
	end
	# TODO: Handle rest of headers, because auth header may be in the rest
	defp process_server_handshake_response(socket, headers) do

		case recvTcp(socket, 0) do
			#{http_response, HttpVersion, integer(), HttpString}
			{:ok, {:http_response, {1,1}, 101, _httpstring}} ->
				process_server_handshake_response(socket, headers)
			# Process headers
			# Required websocket headers
			# Example: {:ok, {:http_header, 24, :"User-Agent", :undefined, "curl/7.35.0"}}
			{:ok, {:http_header, _size, :Upgrade, _reserved, upgrade}} ->
				process_server_handshake_response(socket, %Websocketex.Headers{headers | upgrade: upgrade})
			{:ok, {:http_header, _size, :Connection, _reserved, connection}} ->
				process_server_handshake_response(socket, %Websocketex.Headers{headers | connection: connection})
			{:ok, {:http_header, _size, "Sec-Websocket-Accept", _reserved, accept}} ->
				process_server_handshake_response(socket, %Websocketex.Headers{headers | sec_websocket_accept: accept})
			# Optional headers
			{:ok, {:http_header, _size, "Sec-Websocket-Protocol", _reserved, protocols}} ->
				process_server_handshake_response(socket, %Websocketex.Headers{headers | sec_websocket_protocol: protocols})
			{:ok, {:http_header, _size, "Sec-Websocket-Extensions", _reserved, extensions}} ->
				process_server_handshake_response(socket, %Websocketex.Headers{headers | sec_websocket_extensions: extensions})
			# Store other headers
			{:ok, {:http_header, _size, header_field, _otherfield, value}} ->
				%Websocketex.Headers{rest_of_headers: rest_of_headers} = headers
				rest_of_headers = rest_of_headers ++ [{header_field, value}]
				process_request(socket, %Websocketex.Headers{headers | rest_of_headers: rest_of_headers})
			# If an error occurs receiving
			{:error, reason} -> {:error, reason}
			# If there is no matching case
			:error ->
				close(socket, :protocol_error)
				{:error, "Protocol error. Closing connection."}
			# Other procotol version, must thorw error
			{:ok, {:http_response, {1,0}, _response_code, _httpstring}} ->
				close(socket, :protocol_error)
				{:error, "Protocol error. HTTP/1.0 not supported."}
			# End of Headers
			{:ok, :http_eoh} ->
				# Change socket back to receive raw data
				if is_ssl?(socket) do
					:ssl.setopts(socket, [{:packet, 0}])
				else
					:inet.setopts(socket, [{:packet, 0}])
				end
				{:ok, headers}
			# SSL request on non SSL server socket
			{:ok, {:http_error, _binary}} ->
				close(socket, :protocol_error)
				# Exception
				{:error, "Protocol error. Cannot connect to non SSL/TLS socket."}
		end
	end

	defp recvTcp(socket, length) do
		if Record.is_record(socket, :sslsocket) do
			case :ssl.recv(socket, length) do
				{:ok, packet} -> {:ok, packet}
				{:error, reason} -> {:error, reason}
			end
		else
			case :gen_tcp.recv(socket, length) do
				{:ok, packet} -> {:ok, packet}
				{:error, reason} -> {:error, reason}
			end
		end
	end

	defp acceptTcp(socket) do
		if Record.is_record(socket, :sslsocket) do
			{:ok, sslSocket} = :ssl.transport_accept(socket)
			case :ssl.ssl_accept(sslSocket) do
				:ok -> {:ok, sslSocket}
				{:error, reason} -> {:error, reason}
			end
		else
			:gen_tcp.accept(socket)
		end
	end

	# Send framed data to the WebSocket server
	@doc """
	Sends data over the WebSocket
	## Parameters
	* WebSocket
	* data - text or binary data
	* opcode - :text

	## Examples
				iex> {:ok, websocket} = Websocketex.connect(:ws, 'localhost', 5678)
				iex> Websocketex.send(websocket, "echo", :text)
	"""
	def send(socket, data, opcode) do
		if is_integer(data) do
			data_size = byte_size(:binary.encode_unsigned(data))
		else
			data_size = byte_size(data)
		end
		#data_size = byte_size(data)
		if data_size > @message_max_byte_size do
			close(socket, :large_message)
		else
			if data_size <= @frame_max_size_bytes do
				frame = frame_up(data, opcode, 1)
				sendTcp(socket, frame)
			else
				<<datagram::size(@frame_max_size_bits), rest::binary>> = data
				case get_opcode(opcode) do
					{:ok, opcode_value} ->
						if opcode_is?(opcode_value, :continuation) do
							# frame_up(data, opcode_type, fin bit)
							frame = frame_up(datagram, :continuation, 0)
						else
							# Fragmentation starting
							frame = frame_up(datagram, opcode, 0)
						end
						# Send fragmented frame
						sendTcp(socket, frame)
						# Process the rest of the data
						send(socket, rest, :continuation)
					:error -> raise "Protocol error. Invalid opcode."
				end
			end
		end
	end

	defp sendTcp(socket, packet) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.send(socket, packet)
		else
			:gen_tcp.send(socket, packet)
		end
	end

	defp opcode_is?(opcode, type) do
		case Map.fetch(@opcodes, type) do
			{:ok, value} ->
				if value == opcode do
					true
				else
					false
				end
			{:error} -> false
		end
	end

	defp get_opcode(type) do
		Map.fetch(@opcodes, type)
	end

	defp get_status_code(type) do
		Map.fetch(@status_codes, type)
	end

	defp is_context?(type) do
		current_options = get_agent()
		cond do
			type == :client ->
				current_options.__struct__ == Websocketex.ClientOptions
			type == :server ->
				current_options.__struct__ == Websocketex.ServerOptions
		end
	end

	defp is_ssl?(socket) do
		if Record.is_record(socket, :sslsocket) do
			true
		else
			false
		end
	end

	defp frame_up(data, opcode_type, fin) do
		opcode = nil
		if is_context?(:client) do
			mask = 1
		else # Server context
			mask = 0
		end
		# Get bytes depending if binary or integer
		if is_integer(data) do
			payload_length = byte_size(:binary.encode_unsigned(data))
		else
			payload_length = byte_size(data)
		end
		binary_data = data
		if is_context?(:client) do
			# call masking function
			masking_key = :crypto.strong_rand_bytes(4)
			binary_data = mask_data(masking_key, binary_data)
		end
		case get_opcode(opcode_type) do
			{:ok, value} ->
				opcode = value
				frame = <<fin::size(1), 0::size(3), opcode::size(4), mask::size(1)>>
				cond do
					payload_length <= 125 ->
						bin_payload_length = <<payload_length::size(7)>>
						frame = <<frame::bitstring, bin_payload_length::bitstring>>
					payload_length == 126 ->
						ext_payload_length = <<126::size(7), _last::size(16)>> = payload_length
						frame = <<frame::binary, ext_payload_length::binary>>
					payload_length >= 127 ->
						ext_payload_length = <<127::size(7), _last::size(64)>> = payload_length
						frame = <<frame::binary, ext_payload_length::binary>>
				end
				# Attach masking key or not
				if is_context?(:client) do
					frame = <<frame::binary, masking_key::binary>>
				end
				# If data is a status code then give bit size, else it's text or binary data
				if is_integer(data) and is_context?(:server) do
					bitstring_data = <<binary_data::size(16)>>
					frame = <<frame::bitstring, bitstring_data::bitstring>>
				else
					frame = <<frame::binary, binary_data::binary>>
				end
				frame
			:error -> raise "Protocol error. Invalid opcode."
		end
	end

end

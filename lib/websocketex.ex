defmodule Websocketex do
	use Agent
	require Record
	require Bitwise
	@websocket_version 13
	@timeout 20
	@opcodes %{contiunation: 0x0, text: 0x1, binary: 0x2, connection_close: 0x8, ping: 0x9, pong: 0xA}
	@status_codes %{normal_closure: 1000, going_away: 1001, protocol_error: 1002, invalid_data: 1003, no_code: 1005, abnormal_close: 1006, non_utf8: 1007, policy_violation: 1008, large_message: 1009, missing_extension: 1010, unexpected_condition: 1011, tls_failed: 1015}
	@frame_max_size_bytes 1500
	@frame_max_size_bits @frame_max_size_bytes * 8
	@pending_connections 10

  @moduledoc """
  Documentation for Websocketex.
  """

	def main do
		# Listen socket, in this case
		#[:binary, {:packet, :http_bin}, {:active, false}]
		#{:ok, listenSocket} = Websocketex.listen(5678)
		#{:ok, socket} = Websocketex.accept(listenSocket)
		#Websocketex.send(socket, "HTTP/1.1 200 OK\r\n Connection: close\r\n\r\n")
		#Websocketex.shutdown(socket, :read_write)
		#Websocketex.close(socket)

		# New and improved listening version
		#Websocketex.listen(5678, %Websocketex.ServerOptions{ssl: true, certificate: "domain.crt", key: "domain.key"})
		Websocketex.listen(5678)
		|>
		loop_server

		# View http headers
		#lSocket = Websocketex.listen(5678)
		#{:ok, socket} = :gen_tcp.accept(lSocket)
		#:gen_tcp.recv(socket, 0)

		#start_agent(%Websocketex.ServerOptions{})
		#save_agent("protocols", "test")
		#get_agent()
		#Agent.stop(__MODULE__, :normal)

		#listening to https to see what comes
		#lSocket = listen(5678)
		#{:ok, socket} = :gen_tcp.accept(lSocket)
		#{:ok, {:http_error, binary_data}} = recv(socket, 0)
		#binary_data

		#SSL

		#:ssl.start()
		#{:ok, lSocket} = :gen_tcp.listen(5678, [{:reuseaddr, true}])
		#{:ok, socket} = :gen_tcp.accept(lSocket)
		#case :gen_tcp.accept(lSocket) do
			#{:ok, socket} ->
				#IO.puts "Socket connected."
				#:inet.setopts(socket, [{:active, false}])
				#IO.puts "Opts changed"
				#Successfull recv() on https request returns
				# {:ok, [22, 3, 1, 1, 30, 1, 0, 1, 26, 3, 3, 117, 255, 244, 104, 65, 105, 224, 161,
  			# 117, 108, 129, !"192, 121, 22, 210, 130, 2, 83, 253, 1, 196, 247, 142, 195, 168,
  			# 191, 162, 184, 79, 118, 119, 156, 0, 0, 118, 192, 48, 192, ...]}

				# Actual SSL handshake
				#IO.puts "Handshake"
				#{:ok, sslSocket} = :ssl.ssl_accept(socket, [{:certfile, "domain.crt"}, {:keyfile, "domain.key"}])
				#case :ssl.ssl_accept(socket, [{:certfile, "domain.crt"}, {:keyfile, "domain.key"}], 20) do
					#{:ok, sslSocket} ->
						#IO.puts "Socket secure"
						#IO.puts Record.is_record(socket, :sslsocket)
						#:ssl.recv(sslSocket, 0)
						#:ssl.shutdown(sslSocket, :read_write)
						#:ssl.close(sslSocket)
						#:ssl.stop()
						#IO.puts "SSL stop"
					#{:error, reason} ->
						#IO.puts "Socket insecure"
						#IO.puts Record.is_record(socket, :sslsocket)
						#:gen_tcp.recv(socket, 0)
						#:gen_tcp.shutdown(socket, :read_write)
						#:gen_tcp.close(socket)
				#end
			#end
				#:ssl.recv(sslSocket, 0)
				#:ssl.stop()
				#IO.puts "SSL stop"

			#{:error, reason} -> {:error, reason}
		#end

		#:inet.setopts(socket, [{:active, false}])

		# Actual SSL handshake
		#{:ok, sslSocket} = :ssl.ssl_accept(socket, [])
		#recv(sslSocket, 0)
		#:ssl.stop()

	end

	def client do
		 case Websocketex.connect(:ws, '192.168.1.66', 5678) do
		 		{:ok, websocket} ->
					Websocketex.send(websocket, "Hello", :text)
					IO.puts "Sent: Hello"
					server_response = Websocketex.recv(websocket)
					IO.puts "Received: " <> server_response
					Websocketex.close(websocket)
				{:error, reason} -> {:error, reason}
		 end
	end

	def loop_server(lSocket) do
		IO.puts "Waiting for an incoming connection...."
		case Websocketex.accept(lSocket) do
			{:ok, socket} ->
				IO.puts "Connection received!"
				#recv_loop(socket, [])
				#message = Websocketex.recv(socket)
				#IO.puts message
				Websocketex.send(socket, "echo", :text)
				Websocketex.send(socket, "echo2", :text)
				#Websocketex.send(socket, "Server response 2!", :text)
				#Websocketex.shutdown(socket, :read_write)
				Websocketex.close(socket)
				loop_server(lSocket)
			{:error, reason} ->
				IO.puts reason
				loop_server(lSocket)
		end
	end

	def recv_loop(socket, data) do
		case recvTcp(socket, 2) do
			{:ok, bin} ->
				Websocketex.close(socket)
				<<fin::size(1), rsv1::size(1), rsv2::size(1), rsv3::size(1), opcode::size(4), mask::size(1), payload_length::size(7)>> = bin
				IO.puts fin
				IO.puts rsv1
				IO.puts rsv2
				IO.puts rsv3
				IO.puts opcode
				IO.puts mask
				IO.puts payload_length
				#recv_loop(socket, Enum.concat(data, :binary.bin_to_list(bin)))
			{:error, _reason} -> Enum.to_list(data)
		end
	end
	# TODO: Handle rest of headers a client may send
	defp process_request(socket, headers) do
		case recvTcp(socket, 0) do
			# Get protocol, method and uri
			{:ok, {:http_request, :GET, {:abs_path, _path}, {1,1}}} ->  process_request(socket, headers)
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
			# Ignore any other headers
			{:ok, {:http_header, _size, _header_field, _otherfield, _value}} -> process_request(socket, headers)
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
						:inet.setopts(socket, [{:packet, 0}])

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

	def close(websocket) do
		{:ok, code} = get_status_code(:normal_closure)
		Websocketex.send(websocket, code, :connection_close)
		clean_closure(websocket)
	end

	defp close(socket, status_code_type) do
		{:ok, code} = get_status_code(:status_code_type)
		Websocketex.send(socket, code, :connection_close)
		clean_closure(socket)
	end

	defp clean_closure(socket) do
		shutdown(socket, :read_write)
		case recvTcp(socket, 0) do
			# Server close response
			{:ok, 0} -> closeTcp(socket)
			# Client closed, which SHOULD NOT happen, thus returns a status code to unframe
			{:ok, data} -> handle_frame(data, socket, <<>>, -1)
			{:error, reason} -> {:error, reason}
		end
	end

	defp closeTcp(socket) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.close(socket)
		else
			:gen_tcp.close(socket)
		end
	end

	def listen(port, server_options) do
		options = [:binary, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}]
		listen(port, options, server_options)
	end

	def listen(port, options \\ [:binary, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}], server_options \\ %Websocketex.ServerOptions{}) do
		# If the server is configured as an ssl
		if server_options.ssl do
			:ssl.start()
			# Started ssl, check to see if I have the minimum required files for SSL connection
			case Websocketex.ServerOptions.is_ssl_ready?(server_options) do
				true ->
					# Add ssl files to server options
					%Websocketex.ServerOptions{caCertificate: ca, certificate: cert, key: key} = get_agent()
					if is_nil(ca) do
						options = Enum.concat(options, [{:certfile, cert}, {:keyfile, key}])
					else
						options = Enum.concat(options, [{:cacertfile, ca}, {:certfile, cert}, {:keyfile, key}])
					end
					case :ssl.listen(port, options) do
						{:ok, sslSocket} ->
							start_agent(server_options) # save the options
							sslSocket
						{:error, reason} -> {:error, reason}
					end
				false ->
					{:error, "Missing Certificate or Key file."}
			end
		else # plain old TCP sockets
			case :gen_tcp.listen(port, options) do
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
					#IO.puts "Frame IN!"
					<<fin::size(1), _rsv1::size(1), _rsv2::size(1), _rsv3::size(1), opcode::size(4), mask::size(1), payload_length::size(7)>> = frame
					#IO.puts "First 16 OK!"
					# If mask is 0, then you must terminate. All client packets must be masked.
					# In server context only
					if mask == 0 and is_context?(:server) do
						close(socket, :protocol_error)
					else

						if mask == 1 and is_context?(:client) do
							close(socket, :protocol_error)
						else
							#IO.puts "Has a mask! OK!"
							payload_data_length = check_payload_length(payload_length, socket)
							# Check if the frame has a mask
							masking_key = cond do
								mask == 1 ->
									# Get the next 4 byes of the masking key
									case recvTcp(socket, 4) do
										{:ok, masking_key} ->
											#IO.puts "Masking key OK!"
											masking_key
									end
								mask == 0 ->
									0
								true -> 0
							end
							#IO.puts "handle_frame OK!"
							#IO.puts "Payload Data Lenght: " <> Integer.to_string(payload_data_length)
							#IO.puts "Masing key: " <> Enum.join(:erlang.binary_to_list(masking_key))
							# Now get the data in the frame
							case recvTcp(socket, payload_data_length) do
								{:ok, rest} ->
									cond do
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
					case get_status_code(:protocol_error) do
						{:ok, protocol_error} ->
							status_code = Integer.to_string(protocol_error)
							Websocketex.send(socket, status_code, opcode)
						:error -> "Protocol error. Invalid status code."
					end
				end
			opcode_is?(opcode, :binary) ->
				data
		end
	end

	# Determines which type of control frame is received, if any, and processes them accordingly
	defp handle_control_frames(opcode, socket, data) do
		cond do
			opcode_is?(opcode, :connection_close) ->
				case get_status_code(:policy_violation) do
					{:ok, code} ->
						Websocketex.send(socket, code, opcode)
					:error -> raise "Protocol error. Invalid status code."
				end
			# Ping, send pong
			opcode_is?(opcode, :ping) ->
				Websocketex.send(socket, data, opcode)
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
		#IO.puts "unmask in"
		if is_integer(data) do
			data_size = bit_size(:binary.encode_unsigned(data)) # Data size in bits
		else
			data_size = bit_size(data) # Data size in bits
		end
		#IO.puts "data size: " <> Integer.to_string(data_size)
		if data_size >= 32 do # If the remaining data is > 32
			#IO.puts "Size greater than 32"
			if is_integer(data) do
				<<datagram::size(32)>> = data
			else
				<<datagram::size(32), rest_data::binary >>  = data
			end
			#IO.puts "Datagram > 32"
			<<keygram::size(32), _rest_key::binary>> = masking_key
			key = keygram
			#IO.puts "Got Keygram > 32"
			unmask_data(masking_key, rest_data, <<acc::binary, Bitwise.bxor(key, datagram)::size(32)>>)
		else
				if data_size > 0 do
					#IO.puts "Size less than 32"
					if is_integer(data) do
						<<datagram::size(data_size), rest_data::binary>>  = :binary.encode_unsigned(data)
					else
						<<datagram::size(data_size), rest_data::binary >>  = data
					end
					#IO.puts "Datagram < 32"
					<<keygram::size(data_size), _rest_key::binary>> = masking_key
					key = keygram
					#IO.puts "Got Keygram < 32"
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

	def connect(protocol, address, port) do
		connect(protocol, address, port, %Websocketex.ClientOptions{})
	end

	def connect(protocol, address, port, path \\ "", options \\ %Websocketex.ClientOptions{}, timeout \\ :infinity) do
		connectTcp(protocol, address, port, path, options, timeout)
	end

	# TODO: Serialize multiple connect's, there can only be one CONNECTING at a time
	# TODO: _Fail Websocket Connection_
	# TODO: Abort
	defp connectTcp(protocol, address, port, path, options, timeout) do
		cond do
			protocol == :ws ->
				case :gen_tcp.connect(address, port, [:binary, {:packet, 0}, {:active, false}], timeout) do
					{:ok, socket} ->
						options = %Websocketex.ClientOptions{options | path: path}
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
				case :ssl.connect(address, port, [{:active, false}], timeout) do
					{:ok, sslSocket} ->
						options = %Websocketex.ClientOptions{options | path: path, ssl: true}
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
		%Websocketex.ClientOptions{path: path, origin: origin, protocols: protocols, extensions: extensions} = options
		{:ok, host} = :inet.gethostname()
		key = Base.encode64(:crypto.strong_rand_bytes(16))
		upgrade_request = "GET " <> "/" <> " HTTP/1.1"
		<> if origin != nil do "\r\nOrigin:http://" <> origin else "" end
		<>"\r\nHost:" <> to_string(host)
		<>"\r\nUpgrade:websocket\r\nConnection:Upgrade"
		<> "\r\nSec-WebSocket-Key:" <> key
		<> "\r\nSec-WebSocket-Version:" <> Integer.to_string(@websocket_version)
		<> if protocols do "Sec-WebSocket-Protocol: " <> Enum.join(protocols, ",") <> "\r\n" else "" end
		<> if extensions do "Sec-WebSocket-Extensions: " <> Enum.join(extensions, ";") <> "\r\n" else "" end
		<> "\r\n\r\n"
		# Send the handshake request to server
		case sendTcp(socket, upgrade_request) do
			:ok ->
				# Handshake sent
				# Get the response from the server
				# Server respondend to handshake
				case process_server_handshake_response(socket, %Websocketex.Headers{}) do
					{:ok, headers} ->
						%Websocketex.Headers{sec_websocket_protocol: server_protocol, sec_websocket_extensions: server_extensions} = headers
						if Websocketex.Headers.check_client_headers(headers, key) and Websocketex.ClientOptions.check_protocol(protocols, server_protocol) and Websocketex.ClientOptions.check_extensions(extensions, server_extensions) do
							# handshake ok
							:ok
						else
							#Failed
							# TODO: Send close frame to server
							close(socket, :protocol_error)
							{:error, "Protocol error. Malformed handshake."}
						end
					{:error, reason} -> {:error, reason}
				end
			{:error, reason} -> {:error, reason}
		end
	end
	# TODO: Handle rest of headers, because auth header may be in the rest
	defp process_server_handshake_response(socket, headers) do
		# Change socket to receive http packets
		:inet.setopts(socket, [{:packet, :http_bin}])

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
			# Ignore any other headers
			#{:ok, {:http_header, _size, _header_field, _otherfield, _value}} -> process_request(socket, headers)
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
				:inet.setopts(socket, [{:packet, 0}])
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
			:ssl.recv(socket, length)
		else
			:gen_tcp.recv(socket, length)
		end
	end

	defp recvTcp(socket, length, timeout) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.recv(socket, length, timeout)
		else
			:gen_tcp.recv(socket, length, timeout)
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
	def send(socket, data, opcode) do
		if is_integer(data) do
			data_size = byte_size(:binary.encode_unsigned(data))
		else
			data_size = byte_size(data)
		end
		#data_size = byte_size(data)
		if data_size <= @frame_max_size_bytes do
			frame = frame_up(data, opcode, 1)
			sendTcp(socket, frame)
		else
			<<datagram::size(@frame_max_size_bits), rest::binary>> = data
			case get_opcode(opcode) do
				{:ok, opcode_value} ->
					if opcode_is?(opcode_value, :contiunation) do
						# frame_up(data, opcode_type, fin bit)
						frame = frame_up(datagram, :contiunation, 0)
					else
						# Fragmentation starting
						frame = frame_up(datagram, opcode, 0)
					end
					send(socket, rest, 0)
				:error -> raise "Protocol error. Invalid opcode."
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
	# TODO: Handle client masking
	defp frame_up(data, opcode_type, fin) do
		#IO.puts data
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
			IO.puts "Client context"
			masking_key = :crypto.strong_rand_bytes(4)
			binary_data = mask_data(masking_key, binary_data)
		end
		case get_opcode(opcode_type) do
			{:ok, value} ->
				opcode = value
				frame = <<fin::size(1), 0::size(3), opcode::size(4), mask::size(1), payload_length::size(7)>>
				#IO.puts "Frame set OK!"
				cond do
					payload_length == 126 ->
						#IO.puts "126 OK"
						ext_payload_length = <<126::size(7), _last::size(16)>> = payload_length
						frame = <<frame::binary, ext_payload_length::binary>>
					payload_length >= 127 ->
						#IO.puts "127 OK"
						ext_payload_length = <<127::size(7), _last::size(64)>> = payload_length
						frame = <<frame::binary, ext_payload_length::binary>>
					true ->
						# When payload length is <= than 125, handled in if-else below. Do nothing.
						true
				end
				# Attach masking key or not
				if is_context?(:client) do
					frame = <<frame::binary, masking_key::binary>>
				end
				cond do
					opcode_is?(opcode, :connection_close) ->
						if is_context?(:client) do
							frame = <<frame::binary, binary_data::binary>>
						else
							frame = <<frame::binary, binary_data::size(16)>>
						end
					opcode_is?(opcode, :ping) ->
						frame = <<frame::binary, binary_data::binary>>
					opcode_is?(opcode, :pong) ->
						frame = <<frame::binary, binary_data::binary>>
					true ->
						frame = <<frame::binary, binary_data::binary>>
				end
				frame
			:error -> raise "Protocol error. Invalid opcode."
		end
	end

end

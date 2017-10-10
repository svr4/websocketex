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


	def loop_server(lSocket) do
		case Websocketex.accept(lSocket) do
			{:ok, socket} ->
				#recv_loop(socket, [])
				message = Websocketex.recv(socket)
				IO.puts message
				Websocketex.send(socket, "Server response 1!", :text)
				Websocketex.send(socket, "Server response 2!", :text)
				#Websocketex.shutdown(socket, :read_write)
				#Websocketex.close(socket)
				#loop_server(lSocket)
			{:error, reason} ->
				IO.puts reason
				#loop_server(lSocket)
		end
	end

	def recv_loop(socket, data) do
		case Websocketex.recv(socket, 2) do
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

	defp process_request(socket, headers) do
		case recv(socket, 0) do
			# Get protocol, method and uri
			{:ok, {:http_request, _method, {:abs_path, _path}, {1,1}}} ->  process_request(socket, headers)
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

	defp send_handshake(socket, headers) do
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
						<> if extensions do "Sec-WebSocket-Extensions: " <> Enum.join(extensions, ",") <> "\r\n" else "" end
						<> "\r\n\r\n")
					# After handshake you must change server opts in order to receive data.
					:inet.setopts(socket, [{:packet, 0}])

				false -> sendTcp(socket, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
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

	defp start_agent(server_options) do

		pid = Process.whereis(__MODULE__)

		if pid == nil do
			Agent.start_link(fn -> server_options end, name: __MODULE__)
		else
			if Process.alive?(pid) do
				stop_agent()
				Agent.start_link(fn -> server_options end, name: __MODULE__)
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

	def close(socket) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.close(socket)
		else
			:gen_tcp.close(socket)
		end
	end

	def listen(port, server_options) do
		options = [:binary, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}]
		Websocketex.listen(port, options, server_options)
	end

	def listen(port, options \\ [:binary, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}], server_options \\ %Websocketex.ServerOptions{}) do
		# If the server is configured as an ssl
		if server_options.ssl do
			:ssl.start()
		end
		case :gen_tcp.listen(port, options) do
			{:ok, listenSocket} ->

				if server_options.ssl do
					if is_nil(server_options.certificate) or is_nil(server_options.key) do
						{:error, "SSL/TLS server requires a Certificate and a Key file."}
					else
						# Save server options into an Agent, so the process state can be accesed throughout functions
						start_agent(server_options)
						listenSocket
					end
				else
					# Save server options into an Agent, so the process state can be accesed throughout functions
					start_agent(server_options)
					listenSocket
				end
			{:error, reason} -> {:error, reason}
		end
	end

	defp accept_helper(socket) do
		case process_request(socket, %Websocketex.Headers{}) do
			{:ok, socket, headers} ->
				# Check if http headers are valid
				if !Websocketex.Headers.check_headers(headers) do
					sendTcp(socket, "HTTP/1.1 400 Bad Request\r\nConnection: closed\r\n\r\n")
				end
				# Try to send the handshake
				case send_handshake(socket, headers) do
					:ok -> {:ok, socket}
					{:error, reason} ->
						sendTcp(socket, "HTTP/1.1 400 Bad Request\r\nConnection: closed\r\n\r\n")
						{:error, reason}
				end
			{:error, reason} -> {:error, reason}
		end
	end

	defp ssl_accept(socket, ca, cert, key) do
		if is_nil(ca) do
			:ssl.ssl_accept(socket, [{:certfile, cert}, {:keyfile, key}], @timeout)
		else
			:ssl.ssl_accept(socket, [{:cacertfile, ca}, {:certfile, cert}, {:keyfile, key}], @timeout)
		end
	end

	def accept(socket) do
		case :gen_tcp.accept(socket) do
			{:ok, socket} ->
				# Get if the server is SSL/TLS capable or not
				%Websocketex.ServerOptions{ssl: is_ssl}	= get_agent()
				# Check if handshake should execute
				if is_ssl do
					%Websocketex.ServerOptions{caCertificate: ca, certificate: cert, key: key} = get_agent()
					case ssl_accept(socket, ca, cert, key) do
 						# It's an ssl connection
						{:ok, sslSocket} -> accept_helper(sslSocket)
						{:error, _reason} ->
							sendTcp(socket, "HTTP/1.1 403 Forbidden\r\nConnection: closed\r\n\r\n")
							# Send error back up
							{:error, "SSL/TLS handshake timedout."}
					end
				else
					accept_helper(socket)
				end

			{:error, reason} -> {:error, reason}
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
					if mask == 0 do
						clean_closure(socket)
						# TODO: Send closure frame to client
					else
						#IO.puts "Has a mask! OK!"
						payload_data_length = check_payload_length(payload_length, socket)
						# Check if the frame has a mask
						masking_key = cond do
							mask == 1 ->
								# Get the next 4 byes of the masking key
								case Websocketex.recv(socket, 4) do
									{:ok, masking_key} ->
										#IO.puts "Masking key OK!"
										masking_key
								end
							mask == 0 ->
								0
						end
						#IO.puts "handle_frame OK!"
						#IO.puts "Payload Data Lenght: " <> Integer.to_string(payload_data_length)
						#IO.puts "Masing key: " <> Enum.join(:erlang.binary_to_list(masking_key))
						# Now get the data in the frame
						case Websocketex.recv(socket, payload_data_length) do
							{:ok, rest} ->
								cond do
									# Fragmentation starts
									# Send the opcode in the function call
									fin == 0 and opcode != 0 ->
										# Concat the fragmented data
										acc = <<acc::binary, rest::binary>>
										# Get the next fragment
										Websocketex.recv(socket, 2)
										|>
										handle_frame(socket, acc, opcode)
									# Not the last frame and a control frame
									fin == 0 and opcode >= 0x8 ->
										data = unmask_data(masking_key, rest)
										handle_control_frames(opcode, socket, data)
										# Get the next fragment
										Websocketex.recv(socket, 2)
										|>
										handle_frame(socket, acc, frag_opcode)
									# Whole bunch of fragmented frames
									fin == 0 and opcode == 0 ->
										# Concat the fragmented data
										acc = <<acc::binary, rest::binary>>
										# Get the next fragment
										Websocketex.recv(socket, 2)
										|>
										handle_frame(socket, acc, frag_opcode)
									#The end of fragments. Return data.
									fin == 1 and opcode == 0 ->
										# Concat data and return
										acc = <<acc::binary, rest::binary>>
										# Return the data
										data = unmask_data(masking_key, acc)
										# Check if data is valid UTF-8 if it's text
										validate_data(frag_opcode, data, socket)
									# An unfragmented frame came in
									fin == 1 and (opcode == 0x1 or opcode == 0x2)->
										# Concat data and return
										acc = <<acc::binary, rest::binary>>
										data = unmask_data(masking_key, acc)
										# Check if data is valid UTF-8 if it's text
										validate_data(opcode, data, socket)
									# An unfragmented frame with a control code
									fin == 1 and opcode >= 0x8 ->
										data = unmask_data(masking_key, acc)
										handle_control_frames(opcode, socket, data)
								end


							{:error, reason} -> {:error, reason}
						end
					end

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
							status_code = Integer.to_string()
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
			opcode_is?(opcode, :close) ->
				case get_status_code(:policy_violation) do
					{:ok, code} ->
						status_code = Integer.to_string(code)
						Websocketex.send(socket, status_code, opcode)
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
		data_size = byte_size(data) * 8 # Data size in bits
		#IO.puts "data size: " <> Integer.to_string(data_size)
		if data_size >= 32 do # If the remaining data is > 32
			#IO.puts "Size greater than 32"
			<<datagram::size(32), rest_data::binary >>  = data
			#IO.puts "Datagram > 32"
			<<keygram::size(32), _rest_key::binary>> = masking_key
			key = keygram
			#IO.puts "Got Keygram > 32"
			unmask_data(masking_key, rest_data, <<acc::binary, Bitwise.bxor(key, datagram)::size(32)>>)
		else
				if data_size > 0 do
					#IO.puts "Size less than 32"
					<<datagram::size(data_size), rest_data::binary >>  = data
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

	# Returns the payload data length in bytes
	defp check_payload_length(payload_length, socket) do
		cond do
			payload_length <= 125 ->
				payload_length

			payload_length == 126 ->
				case Websocketex.recv(socket, 2) do # 16 bits
					{:ok, length} ->
						length
					{:error, reason} -> {:error, reason}
				end
			payload_length == 127 ->
				case Websocketex.recv(socket, 8) do # 64 bits
					{:ok, length} ->
						length
					{:error, reason} -> {:error, reason}
				end
		end
	end

	# Handles all incoming data from clients
	def recv(socket) do
		# Get the first 2 bytes or 16 bits of the frame
		Websocketex.recv(socket, 2)
		|> handle_frame(socket)
	end


	defp clean_closure(socket) do
		Websocketex.shutdown(socket, :read_write)
		case Websocketex.recv(socket, 0) do
			{:ok, 0} -> Websocketex.close(socket)
			{:error, reason} -> {:error, reason}
		end
	end

	def shutdown(socket, how) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.shutdown(socket, how)
		else
			:gen_tcp.shutdown(socket, how)
		end
	end

	def connect(address, port, options) do
		:gen_tcp.connect(address, port, options)
	end

	def connect(address, port, options, timeout) do
		:gen_tcp.connect(address, port, options, timeout)
	end

	def recv(socket, length) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.recv(socket, length)
		else
			:gen_tcp.recv(socket, length)
		end
	end

	def recv(socket, length, timeout) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.recv(socket, length, timeout)
		else
			:gen_tcp.recv(socket, length, timeout)
		end
	end

	# Send framed data to the WebSocket server
	def send(socket, data, opcode) do
		data_size = byte_size(data)
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

	def controlling_process(socket, pid) do
		:gen_tcp.controlling_process(socket, pid)
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

	# TODO: Handle the creation of multiple frames
	defp frame_up(data, opcode_type, fin) do
		#IO.puts data
		opcode = nil
		mask = 0 # For now, need to implement client or server context
		payload_length = byte_size(data)
		binary_data = data
		case get_opcode(opcode_type) do
			{:ok, value} ->
				opcode = value
				frame = <<fin::size(1), 0::size(3), opcode::size(4), mask::size(1), payload_length::size(7)>>
				#IO.puts "Frame set OK!"
				cond do
					payload_length <= 125 ->
						# TODO: Add masking key to frame when client sending data
						#IO.puts "125 OK"
						frame = <<frame::binary, binary_data::binary>>
						#IO.puts "New frame OK"
					payload_length == 126 ->
						# TODO: Addtext masking key to frame when client sending data
						#IO.puts "126 OK"
						ext_payload_length = <<126::size(7), _last::size(16)>> = payload_length
						frame = <<frame::binary, ext_payload_length::binary, 0::size(32), binary_data::binary>>
					payload_length >= 127 ->
						# TODO: Add masking key to frame when client sending data
						#IO.puts "127 OK"
						ext_payload_length = <<127::size(7), _last::size(64)>> = payload_length
						frame = <<frame::binary, ext_payload_length::binary, 0::size(32), binary_data::binary>>
				end
				frame
			:error -> raise "Protocol error. Invalid opcode."
		end
	end

end

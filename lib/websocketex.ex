defmodule Websocketex do
	use Agent
	require Record
	@websocket_version 13
	@timeout 20

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
  			# 117, 108, 129, 192, 121, 22, 210, 130, 2, 83, 253, 1, 196, 247, 142, 195, 168,
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
				Websocketex.shutdown(socket, :read_write)
				Websocketex.close(socket)
				loop_server(lSocket)
			{:error, reason} ->	
				IO.puts reason
				loop_server(lSocket)
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
			:error -> Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: close\r\n\r\n")
			# Other procotol version, must thorw error		
			{:ok, {:http_request, _method, {:abs_path, _path}, {1,0}}} -> Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: close\r\n\r\n")
			# End of Headers
			{:ok, :http_eoh} -> {:ok, socket, headers}
			# SSL request on non SSL server socket
			{:ok, {:http_error, _binary}} ->
				# Refuse, close connection on client
				Websocketex.send(socket, "HTTP/1.1 403 Forbidden\r\n Connection: close\r\n\r\n")
				# Exception
				{:error, "Protocol error. Cannot connect to non SSL/TLS socket."}
		end
	end

	# TODO: Implement TLS/SSL socket handshake
	defp send_handshake(socket, headers) do
		if String.to_integer(headers.sec_websocket_version) != @websocket_version do
			Websocketex.send(socket, "HTTP/1.1 426 Upgrade Required\r\n Sec-WebSocket-Version: " <> Integer.to_string(@websocket_version) <> "\r\n\r\n")
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
					Websocketex.send(socket, "HTTP/1.1 101 Switching Protocols\r\n Upgrade: websocket\r\n Connection: Upgrade\r\n Sec-WebSocket-Accept: " 
						<> sec_websocket_accept
						<> if protocols do "Sec-WebSocket-Protocol: " <> Enum.join(protocols, ",") <> "\r\n" else "" end
						<> if extensions do "Sec-WebSocket-Extensions: " <> Enum.join(extensions, ",") <> "\r\n" else "" end
						<> "\r\n\r\n")

				false -> Websocketex.send(socket, "HTTP/1.1 403 Forbidden\r\n Connection: close\r\n\r\n")
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
		options = [:list, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}]
		Websocketex.listen(port, options, server_options)
	end

	def listen(port, options \\ [:list, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}], server_options \\ %Websocketex.ServerOptions{}) do
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
					Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: closed\r\n\r\n")
				end
				# Try to send the handshake
				case send_handshake(socket, headers) do
					:ok -> {:ok, socket}
					{:error, reason} -> 
						Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: closed\r\n\r\n")
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
							Websocketex.send(socket, "HTTP/1.1 403 Forbidden\r\n Connection: closed\r\n\r\n")
							# Send error back up
							{:error, "SSL/TLS handshake timedout."}
					end
				else
					accept_helper(socket)
				end
	
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

	def send(socket, packet) do
		if Record.is_record(socket, :sslsocket) do
			:ssl.send(socket, packet)
		else
			:gen_tcp.send(socket, packet)
		end
	end

	def controlling_process(socket, pid) do
		:gen_tcp.controlling_process(socket, pid)
	end

end

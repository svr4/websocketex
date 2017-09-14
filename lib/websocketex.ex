defmodule Websocketex do
	@websocket_version 13

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
		Websocketex.listen(5678)
		|>
		loop_server

		#listening to https to see what comes
		#lSocket = listen(5678)
		#{:ok, socket} = :gen_tcp.accept(lSocket)
		#{:ok, {:http_error, binary_data}} = recv(socket, 0)
		#binary_data

		#SSL

		#:ssl.start()
		#{:ok, lSocket} = :gen_tcp.listen(5678, [{:reuseaddr, true}])
		#{:ok, socket} = :gen_tcp.accept(lSocket)

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
			{:error, reason} -> {:error, reason}
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
			{:ok, {:http_error, binary_data}} -> {:ok, {:http_error, binary_data}}
			# If there is no matching case
			:error -> Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: close\r\n\r\n")
			# Other procotol version, must thorw error		
			{:ok, {:http_request, _method, {:abs_path, _path}, {1,0}}} -> Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: close\r\n\r\n")
			# End of Headers
			{:ok, :http_eoh} -> {:ok, socket, headers}
		end
	end

	# TODO: Implement TLS/SSL socket handshake
	# TODO: Implement Origin validation
	# TODO: Implement Version validation
	# TODO: Implement Subprotocol validation and response
	# TODO: Implement Extensions validation adn response
	defp send_handshake(socket, headers) do
		# String defined in RFC 6455 to concatinate with Sec-Websocket-key
		accept_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		# Concatinate the key in the headers with the accept string,  hash that with SHA-1 and finally base64 encode it.
		sec_websocket_accept = Base.encode64(:crypto.hash(:sha, headers.sec_websocket_key <> accept_string))
		Websocketex.send(socket, "HTTP/1.1 Switching Protocols\r\n Upgrade: websocket\r\n Connection: Upgrade\r\n Sec-Websocket-Accept: " <> sec_websocket_accept <> "\r\n\r\n")
	end

	def close(socket) do
		:gen_tcp.close(socket)
	end

	#[:binary, {:packet, 0}, {:active, false}]
	def listen(port, options \\ [:list, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}]) do
		case :gen_tcp.listen(port, options) do
			{:ok, listenSocket} -> listenSocket
			{:error, reason} -> {:error, reason}
		end
	end

	def accept(socket) do
		case :gen_tcp.accept(socket) do
			{:ok, socket} -> 
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
			{:error, reason} -> {:error, reason}
		end
	end

	def accept(socket, timeout) do	
		case :gen_tcp.accept(socket, timeout) do
			{:ok, socket} -> 
				case process_request(socket, %Websocketex.Headers{}) do
					{:ok, socket, headers} -> 
						# Check if http headers are valid 
						if !Websocketex.Headers.check_headers(headers) do
							Websocketex.send(socket, "HTTP/1.1 400 Bad Request\r\n Connection: closed\r\n\r\n")
						end
						{:ok, socket}
					{:error, reason} -> {:error, reason}
				end
			{:error, reason} -> {:error, reason}
		end
	end

	def shutdown(socket, how) do
		:gen_tcp.shutdown(socket, how)
	end

	def connect(address, port, options) do
		:gen_tcp.connect(address, port, options)
	end

	def connect(address, port, options, timeout) do
		:gen_tcp.connect(address, port, options, timeout)
	end

	def recv(socket, length) do
		:gen_tcp.recv(socket, length)
	end

	def recv(socket, length, timeout) do
		:gen_tcp.recv(socket, length, timeout)
	end

	def send(socket, packet) do
		:gen_tcp.send(socket, packet)
	end

	def controlling_process(socket, pid) do
		:gen_tcp.controlling_process(socket, pid)
	end

end

defmodule Websocketex do
  @moduledoc """
  Documentation for Websocketex.
  """

	def main do
		# Listen socket, in this case	
		#[:binary, {:packet, :http_bin}, {:active, false}]
		{:ok, listenSocket} = listen(5678)
		{:ok, socket} = accept(listenSocket)
		Websocketex.send(socket, "HTTP/1.1 200 OK\r\n Connection: close\r\n\r\n")
		shutdown(socket, :read_write)
		close(socket)
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
		end
	end

	def close(socket) do
		:gen_tcp.close(socket)
	end

	#[:binary, {:packet, 0}, {:active, false}]
	def listen(port, options \\ [:list, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}]) do
		:gen_tcp.listen(port, options)
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
						{:ok, socket}
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

defmodule Websocketex do
  @moduledoc """
  Documentation for Websocketex.
  """

	def main do
		# Listen socket, in this case	
		#[:binary, {:packet, :http_bin}, {:active, false}]
		{:ok, listenSocket} = listen(5678)
		{:ok, socket} = accept(listenSocket)
		#{:ok, {:http_request, :GET, {:abs_path, "/"}, {1, 1}}}
		#case recv(socket, 0) do
			#{:ok, packet} -> packet
			#{:error, reason} -> reason
			#_ -> IO.puts "WTF"
		#end
		#{:ok, httpPacket} = recv(socket, 0)
		recv(socket, 0)
		recv(socket, 0)
		#:gen_tcp.send(socket, "HTTP/1.1 200 OK \r\n")
		#shutdown(socket, :read_write)
		#close(socket)
		#{http_request, http_method, http_uri, http_version} = httpPacket
	end

	def close(socket) do
		:gen_tcp.close(socket)
	end

	#[:binary, {:packet, 0}, {:active, false}]
	def listen(port, options \\ [:list, {:packet, :http_bin}, {:active, false}, {:reuseaddr, true}]) do
		:gen_tcp.listen(port, options)
	end

	def accept(socket) do
		:gen_tcp.accept(socket)
	end

	def accept(socket, timeout) do
		:gen_tcp.accept(socket, timeout)
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

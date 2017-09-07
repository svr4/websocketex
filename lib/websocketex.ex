defmodule Websocketex do
  @moduledoc """
  Documentation for Websocketex.
  """

	def main do
		# Listen socket, in this case
		{:ok, listenSocket} = listen(5678, [:binary, {:packet, :http_bin}, {:active, false}])
		{:ok, socket} = accept(listenSocket)
		#{:ok, {:http_request, :GET, {:abs_path, "/"}, {1, 1}}}
		recv(socket, 0)
		#case recv(socket, 0) do
			#{:ok, packet} -> IO.puts packet
			#{:error, reason} -> IO.puts reason
			#_ -> IO.puts "WTF"
		#end
		:gen_tcp.send(socket, "HTTP/1.1 200 OK \r\n")
		close(socket)
		
	end

	'''
	def server_loop({socket}) do	
		{:ok, socket} = accept(socket)
		receive_loop(socket, [])
		close(socket)
		server_loop(socket)
	end

	def receive_loop(socket, bs \\ []) do
		case recv(socket, 0) do
			{:ok, packet} -> receive_loop(socket, [bs, packet])
			{:error, reason} -> {:error, reason}
		end
	end
	'''
	def close(socket) do
		#shutdown(socket, :read_write)
		:gen_tcp.close(socket)
	end

	#[:binary, {:packet, 0}, {:active, false}]
	def listen(port, options \\ []) do
		case :gen_tcp.listen(port, options) do
			{:ok, listenSocket} -> {:ok, listenSocket}
			{:error, reason} -> 
				raise reason
		end
	end

	def accept(socket) do
		case :gen_tcp.accept(socket) do
			{:ok, socket} -> {:ok, socket}
			{:error, reason} -> raise reason
		end
	end

	def accept(socket, timeout) do
		case :gen_tcp.accept(socket, timeout) do
			{:ok, socket} -> {:ok, socket}
			{:error, reason} ->	raise reason
		end
	end

	def shutdown(socket, how) do
		case :gen_tcp.shutdown(socket, how) do
			:ok -> :ok
			{:error, reason} ->
				raise reason
		end
	end

	def connect(address, port, options) do
		case :gen_tcp.connect(address, port, options) do
			{:ok, socket} ->
				{socket}
			{:error, reason} ->
				raise reason
		end
	end

	def connect(address, port, options, timeout) do
		case :gen_tcp.connect(address, port, options, timeout) do
			{socket} ->
				{socket}
			{:error, reason} ->
				raise reason
		end
	end

	def recv(socket, length) do
		:gen_tcp.recv(socket, length)
	end

	def recv(socket, length, timeout) do
		case :gen_tcp.recv(socket, length, timeout) do
			{:ok, packet} -> 
				{:ok, packet}

			{:error, reason} ->
				raise reason
		end 
	end

	def send(socket, packet) do
		case :gen_tcp.send(socket, packet) do
			{:error, reason} ->
				raise reason
		end
	end

	def controlling_process(socket, pid) do
		case :gen_tcp.controlling_process(socket, pid) do
			{:error, reason} ->
				raise reason
		end
	end

end

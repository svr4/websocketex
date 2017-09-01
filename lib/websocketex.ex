defmodule Websocketex do
  @moduledoc """
  Documentation for Websocketex.
  """

	def main do
		{:ok, listenSocket} = listen(5678)
		{:ok, socket} = accept(listenSocket)
		case recv(socket, 0) do
			{:ok, packet} -> IO.puts packet
			{:error, reason} -> IO.puts reason
		end
	end

	def close(socket) do
		shutdown(socket, :read_write)
		:gen_tcp.close(socket)
	end

	def listen(port, options \\ [:binary, {:packet, 0}, {:active, false}]) do
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
			{:ok, socket} ->
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
				{packet}

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

defmodule Websocketex.ClientOptions do
  # Struct containing various client options
	defstruct protocols: nil, extensions: nil, origin: nil, ssl: false, path: nil, query: nil

	def check_protocol(client_protocols, server_protocol) do
		if client_protocols == nil and server_protocol == nil do
			true
		else
			if client_protocols == nil or server_protocol == nil do
				false
			else
				Enum.member?(client_protocols, server_protocol)
			end
		end
	end

	def check_extensions(client_extensions, server_extensions) do
		if client_extensions == nil and server_extensions == nil do
			true
		else
			if client_extensions == nil or server_extensions == nil do
				false
			else
				extensions_match = true
				server_extensions = String.split(server_extensions, ",")
				Enum.map(client_extensions, fn(client_extension) ->
					extensions_match = extensions_match and Enum.member?(server_extensions, client_extension)
				end)
				extensions_match
			end
		end
	end

end

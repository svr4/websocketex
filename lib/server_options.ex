defmodule Websocketex.ServerOptions do

	# Struct containing various server options
	defstruct protocols: nil, extensions: nil, origins: ["*"], ssl: false, caCertificate: nil, certificate: nil, key: nil, socket_options: []

	def is_ssl_ready?(server_options) do
		cond do
			server_options.key == nil -> false
			server_options.certificate == nil -> false
			true -> true
		end
	end
end

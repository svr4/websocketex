defmodule Websocketex.Headers do
	# Required: host, upgrade, connection, sec_websocket_key, sec_websocket_version
	# Optional: origin, sec_websocket_protocol, sec_websocket_extensions
	defstruct host: nil, upgrade: nil, connection: nil, sec_websocket_key: nil, sec_websocket_version: nil, origin: nil, sec_websocket_protocol: nil, sec_websocket_extensions: nil


	def check_headers(headers) do
		cond do
			headers.host == nil || headers.host == "" -> false
			headers.upgrade == nil || headers.upgrade == "" -> false
			headers.connection == nil || headers.connection == "" -> false
			headers.sec_websocket_key == nil || headers.sec_websocket_key == "" -> false
			headers.sec_websocket_version == nil || headers.sec_websocket_version == "" -> false
			true -> true
		end
	end
end

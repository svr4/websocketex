defmodule Websocketex.Headers do
	# Required: host, upgrade, connection, sec_websocket_key, sec_websocket_version
	# Optional: origin, sec_websocket_protocol, sec_websocket_extensions
	defstruct host: nil, upgrade: nil, connection: nil, sec_websocket_key: nil, rest_of_headers: [], path: nil, query: nil, sec_websocket_version: nil, origin: nil, sec_websocket_accept: nil, sec_websocket_protocol: nil, sec_websocket_extensions: nil


	def check_server_headers(headers) do
		cond do
			headers.host == nil || headers.host == "" -> false
			headers.upgrade == nil || headers.upgrade == "" || headers.upgrade != "websocket"-> false
			headers.connection == nil || headers.connection == "" || headers.connection != "Upgrade" -> false
			headers.sec_websocket_key == nil || headers.sec_websocket_key == "" -> false
			headers.sec_websocket_version == nil || headers.sec_websocket_version == "" -> false
			true -> true
		end
	end

	def check_client_headers(headers, key) do
		cond do
			headers.upgrade == nil || headers.upgrade == "" || headers.upgrade != "websocket" -> false
			headers.connection == nil || headers.connection == "" || headers.connection != "Upgrade" -> false
			headers.sec_websocket_accept == nil || headers.sec_websocket_accept == "" || Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) != headers.sec_websocket_accept -> false
			true -> true
		end
	end

end

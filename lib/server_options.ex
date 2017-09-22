defmodule Websocketex.ServerOptions do
	
	# Struct containing various server options
	defstruct protocols: nil, extensions: nil, origins: ["*"]
end

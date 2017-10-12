defmodule Websocketex.ClientOptions do
  # Struct containing various client options
	defstruct protocols: nil, extensions: nil, origin: nil, ssl: false, path: nil
end

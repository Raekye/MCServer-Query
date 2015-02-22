local PACKET_TYPE_HANDSHAKE = 9
local PACKET_TYPE_STAT = 0

local PACKET_MAGIC = { 0xFE, 0xFD }
local PACKET_STAT_PADDING_1 = { 0x73, 0x70, 0x6C, 0x69, 0x74, 0x6E, 0x75, 0x6D, 0x00, 0x80, 0x00 }
local PACKET_STAT_PADDING_2 = { 0x01, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x5F, 0x00, 0x00 }

local CHALLENGE_TOKEN = os.time()

local g_UDPSocket = nil
local g_IniFile = nil

function Initialize(Plugin)
	Plugin:SetName("Query")
	Plugin:SetVersion(1)

	-- Use the InfoReg shared library to process the Info.lua file:
	dofile(cPluginManager:GetPluginsPath() .. "/InfoReg.lua")
	RegisterPluginInfoCommands()
	RegisterPluginInfoConsoleCommands()

	local Callbacks =
	{
		OnReceivedData = function (a_Endpoint, a_Data, a_RemotePeer, a_RemotePort)
			HandlePacket(a_Data, a_RemotePeer, a_RemotePort)
		end,

		OnError = function (a_Endpoint, a_ErrorCode, a_ErrorMsg)
			LOG("Error in Query UDP: " .. a_ErrorCode .. " (" .. a_ErrorMsg .. ")")
		end,
	}

	g_IniFile = cIniFile()
	g_IniFile:ReadFile("settings.ini")

	if g_IniFile:GetValueSetB("Query", "Enabled", true) then
		local Port = g_IniFile:GetValueSetI("Query", "Port", 25565)
		g_UDPSocket = cNetwork:CreateUDPEndpoint(Port, Callbacks)
		g_UDPSocket:EnableBroadcasts()
		LOG("Started query server on port " .. tostring(Port) .. "/udp.")
	else
		LOG("Not starting query server; disabled in settings.ini.")
	end

	g_IniFile:WriteFile("settings.ini")

	LOG("Initialized " .. Plugin:GetName() .. " v." .. Plugin:GetVersion())
	return true
end

function OnDisable()
	if g_UDPSocket ~= nil then
		g_UDPSocket:Close()
		g_UDPSocket = nil
	end
	LOG("Disabled Query!")
end

function UDPSend(a_Data, a_Host, a_Port)
	local Callbacks =
	{
		OnError = function (a_Endpoint, a_ErrorCode, a_ErrorMsg)
			LOG("Error in Query UDP sending: " .. a_ErrorCode .. " (" .. a_ErrorMsg .. ")")
		end,

		OnReceivedData = function ()
			-- ignore
		end,
	}
	g_UDPSocket:Send(a_Data, a_Host, a_Port)
end

function HandlePacket(a_Data, a_Host, a_Port)
	if not(PacketHasMagic(a_Data)) then
		return
	end
	local PacketType = a_Data:byte(3)
	if PacketType == PACKET_TYPE_HANDSHAKE then
		HandlePacketHandshake(a_Data, a_Host, a_Port)
	elseif PacketType == PACKET_TYPE_STAT then
		HandlePacketStat(a_Data, a_Host, a_Port)
	end
end

function HandlePacketHandshake(a_Data, a_Host, a_Port)
	local SessionId = PacketReadInt(a_Data:sub(4))
	local Data = PacketCreate(PACKET_TYPE_HANDSHAKE, SessionId, tostring(CHALLENGE_TOKEN) .. "\0")
	UDPSend(Data, a_Host, a_Port)
end

function HandlePacketStat(a_Data, a_Host, a_Port)
	local SessionId = PacketReadInt(a_Data:sub(4))
	local SuppliedTokenBytes = PacketReadInt(a_Data:sub(8))
	local SuppliedToken = 0
	for i = 1, 4 do
		SuppliedToken = SuppliedToken * (2 ^ 8) + SuppliedTokenBytes[i]
	end
	if SuppliedToken ~= CHALLENGE_TOKEN then
		return
	end

	if a_Data:len() == 11 then
		HandleBasicStat(SessionId, a_Host, a_Port)
	elseif a_Data:len() == 15 then
		HandleFullStat(SessionId, a_Host, a_Port)
	end
end

function HandleBasicStat(a_SessionId, a_Host, a_Port)
	local Stat = StatData()
	local Message =
	{
		Stat["hostname"],
		Stat["gametype"],
		Stat["map"],
		Stat["numplayers"],
		Stat["maxplayers"],
		Stat["hostport"],
		Stat["hostip"],
	}
	local Data = PacketCreate(PACKET_TYPE_STAT, a_SessionId, table.concat(Message, "\0") .. "\0")
	UDPSend(Data, a_Host, a_Port)
end

function HandleFullStat(a_SessionId, a_Host, a_Port)
	local Players = {}
	cRoot:Get():ForEachPlayer(function (a_Player)
		if #Players < 16 then
			Players[#Players + 1] = a_Player:GetName()
		end
	end)

	local Message = string.char(unpack(PACKET_STAT_PADDING_1))

	for k, v in pairs(StatData()) do
		Message = Message .. string.format("%s\0%s\0", k, v)
	end
	Message = Message .. "\0"

	Message = Message .. string.char(unpack(PACKET_STAT_PADDING_2))

	Message = Message .. table.concat(Players, "\0") .. "\0\0"

	local Data = PacketCreate(PACKET_TYPE_STAT, a_SessionId, Message)
	UDPSend(Data, a_Host, a_Port)
end

function StatData()
	local Server = cRoot:Get():GetServer()
	local PluginManager = cRoot:Get():GetPluginManager()

	-- currently hardcoded
	local Version = "1.8"
	local Plugins = {}
	for k, v in pairs(PluginManager:GetAllPlugins()) do
		if v ~= false then
			Plugins[#Plugins + 1] = string.format("%s v%s", k, tostring(v:GetVersion()))
		end
	end

	-- these keys are the ones in the key-value section of a full stat as listed in http://wiki.vg/Query
	return {
		-- actually the motd, but called hostname for some reason
		hostname = Server:GetDescription(),

		-- hardcoded as per http://wiki.vg/Query
		gametype = "SMP",

		-- hardcoded as per http://wiki.vg/Query
		game_id = "MINECRAFT",

		version = Version,
		plugins = string.format("MCServer %s: %s", Version, table.concat(Plugins, "; ")),
		map = cRoot:Get():GetDefaultWorld():GetName(),
		numplayers = tostring(Server:GetNumPlayers()),
		maxplayers = tostring(Server:GetMaxPlayers()),
		hostport = g_IniFile:GetValue("Server", "Ports"),

		-- from MCServer source, file src/OSSupport/ServerHandleImpl.cpp
		-- in cServerHandleImpl::Listen(UInt16 a_Port)
		-- `memset(&name, 0, sizeof(name))` binds socket to all interfaces
		hostip = "0.0.0.0",
	}
end

function PacketCreate(a_PacketType, a_SessionId, a_Message)
	return string.char(a_PacketType) .. string.char(unpack(a_SessionId)) .. a_Message
end

function PacketHasMagic(a_Data)
	return a_Data:byte(1) == PACKET_MAGIC[1] and a_Data:byte(2) == PACKET_MAGIC[2]
end

function PacketReadInt(a_Data)
	local x  = {}
	for i = 1, 4 do
		b = a_Data:byte(i)
		if b == nil then
			x[i] = 0
		else
			x[i] = b
		end
	end
	return x
end

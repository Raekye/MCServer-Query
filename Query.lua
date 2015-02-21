local PACKET_TYPE_HANDSHAKE = 9
local PACKET_TYPE_STAT = 0

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
	local Data = PacketCreate(PACKET_TYPE_HANDSHAKE, SessionId, tostring(CHALLENGE_TOKEN) .. string.char(0))
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

	local Server = cRoot:Get():GetServer()

	local MOTD = Server:GetDescription()
	local GameType = "SMP"
	local Map = cRoot:Get():GetDefaultWorld():GetName()
	local NumPlayers = tostring(Server:GetNumPlayers())
	local MaxPlayers = tostring(Server:GetMaxPlayers())
	local HostPort = g_IniFile:GetValue("Server", "Ports")
	local HostIp = "127.0.0.1"

	local Message = { MOTD, GameType, Map, NumPlayers, MaxPlayers, HostPort, HostIp }
	local Data = PacketCreate(PACKET_TYPE_STAT, SessionId, table.concat(Message, "\0") .. string.char(0))
	UDPSend(Data, a_Host, a_Port)
end

function PacketCreate(a_PacketType, a_SessionId, a_Message)
	return string.char(a_PacketType) .. string.char(unpack(a_SessionId)) .. a_Message
end

function PacketHasMagic(a_Data)
	return a_Data:byte(1) == tonumber("fe", 16) and a_Data:byte(2) == tonumber("fd", 16)
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

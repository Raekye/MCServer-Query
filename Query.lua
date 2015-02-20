local PACKET_TYPE_HANDSHAKE = 9
local PACKET_TYPE_STAT = 0

local g_UDPSocket = nil
local g_ChallengeTokenTime = 0
local g_ChallengeToken = nil

function Initialize(Plugin)
	Plugin:SetName("Query")
	Plugin:SetVersion(1)
	-- Use the InfoReg shared library to process the Info.lua file:
	dofile(cPluginManager:GetPluginsPath() .. "/InfoReg.lua")
	RegisterPluginInfoCommands()
	RegisterPluginInfoConsoleCommands()

	-- Seed the random generator:
	math.randomseed(os.time())

	local Callbacks =
	{
		OnReceivedData = function (a_Endpoint, a_Data, a_RemotePeer, a_RemotePort)
			HandlePacket(a_Data, a_RemotePeer, a_RemotePort)
		end,

		OnError = function (a_Endpoint, a_ErrorCode, a_ErrorMsg)
			LOG("Error in Query UDP: " .. a_ErrorCode .. " (" .. a_ErrorMsg .. ")")
		end,
	}

	local Port = 25565
	g_UDPSocket = cNetwork:CreateUDPEndpoint(Port, Callbacks)
	g_UDPSocket:EnableBroadcasts()

	LOG("Initialized " .. Plugin:GetName() .. " v." .. Plugin:GetVersion())
	return true
end

function OnDisable()
	g_UDPSocket:Close()
	g_UDPSocket = nil
	LOG("Query server closed.")
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
	local Token = ChallengeToken(a_Host, a_Port)
	local Data = PacketCreate(PACKET_TYPE_HANDSHAKE, SessionId, tostring(Token) .. string.char(0))
	UDPSend(Data, a_Host, a_Port)
end

function HandlePacketStat(a_Data, a_Host, a_Port)
	local SessionId = PacketReadInt(a_Data:sub(4))
	local Token = ChallengeToken(a_Host, a_Port)
	local SuppliedTokenBytes = PacketReadInt(a_Data:sub(8))
	local SuppliedToken = 0
	for i = 1, 4 do
		SuppliedToken = SuppliedToken * (2 ^ 8) + SuppliedTokenBytes[i]
	end
	if SuppliedToken == Token then
		local Server = cRoot:Get():GetServer()
		local MOTD = Server:GetDescription()
		local GameType = "SMP"
		local Map = "world"
		local NumPlayers = tostring(Server:GetNumPlayers())
		local MaxPlayers = tostring(Server:GetMaxPlayers())
		local HostPort = "25565"
		local HostIp = "127.0.0.1"
		local Message = { MOTD, GameType, Map, NumPlayers, MaxPlayers, HostPort, HostIp }
		local Data = PacketCreate(PACKET_TYPE_STAT, SessionId, table.concat(Message, "\0") .. string.char(0))
		UDPSend(Data, a_Host, a_Port)
	end
end

function PacketCreate(a_PacketType, a_SessionId, a_Message)
	return string.char(a_PacketType) .. string.char(unpack(a_SessionId)) .. a_Message
end

function PacketHasMagic(a_Data)
	return a_Data:byte(1) == tonumber("fe", 16) and a_Data:byte(2) == tonumber("fd", 16)
end

function ChallengeToken(a_Host, a_Port)
	-- currently challenge token not bound to host or port
	if os.time() - g_ChallengeTokenTime > 30 then
		g_ChallengeTokenTime = os.time()
		g_ChallengeToken = math.random(0, 2 ^ 15 - 1)
	end
	return g_ChallengeToken
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

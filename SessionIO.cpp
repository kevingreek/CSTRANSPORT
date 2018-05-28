#include <sstream>
#include <vector>
#include <thread>
#include <random>
#include <fstream>

#include "SessionIO.hpp"
#include "TextHelp.hpp"

#include "sha1.hpp"
#include <Solver\Fake\Fake_Solver.hpp>

bool SessionIO::OneReg = true;

char g_buff[200000] = { 0 };

using namespace std::placeholders;
SessionIO::SessionIO() : InputServiceResolver_(io_service_server_), OutputServiceResolver_(io_service_client_) ,
						factory(),solver(nullptr)
{
	Initialization();
}

void SessionIO::Initialization()
{
	boost::property_tree::read_ini("Configure.ini", config);
	const boost::property_tree::ptree & host_Input = config.get_child("hostInput");
	udp::resolver::query query_send(udp::v4(), host_Input.get<std::string>("ip"), host_Input.get<std::string>("port", "9001"));
	InputServiceRecvEndpoint_ = *InputServiceResolver_.resolve(query_send);
	InputServiceSocket_ = new udp::socket(io_service_server_, InputServiceRecvEndpoint_);
	boost::asio::ip::udp::socket::receive_buffer_size recvBuff(6553600);
	InputServiceSocket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	InputServiceSocket_->set_option(recvBuff);

	InputServiceSocket_->get_option(recvBuff);

	const boost::property_tree::ptree & host_Output = config.get_child("hostOutput");
	udp::resolver::query query_recv(udp::v4(), host_Output.get<std::string>("ip"), host_Output.get<std::string>("port", "9000"));
	OutputServiceRecvEndpoint_ = *OutputServiceResolver_.resolve(query_recv);
	OutputServiceSocket_ = new udp::socket(io_service_client_, OutputServiceRecvEndpoint_);
	boost::asio::ip::udp::socket::send_buffer_size sendBuff(6553600);
	OutputServiceSocket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	InputServiceSocket_->set_option(sendBuff);

	const boost::property_tree::ptree & server = config.get_child("server");
	udp::resolver::query query_serv(udp::v4(), server.get<std::string>("ip"), server.get<std::string>("port", "6000"));
	OutputServiceServerEndpoint_ = *OutputServiceResolver_.resolve(query_serv);

	m_nodesRing.resize(500);
	BackData_.resize(100);

	DefiningNode_ = LevelNodes::Normal;
	GenerationHash();

	SizePacketHeader = ñalcSumHeader();
	SizePacketHeader2 = ñalcSumHeader();

	myIp = InputServiceRecvEndpoint_.address().to_string();
 
}

void SessionIO::DefiningNode(unsigned int init)
{
	DefiningNode_ = init;
}

void SessionIO::SolverSendData(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size, unsigned int cmd)
{
	switch (cmd)
	{
		case CommandList::SendBlock:
		{
			SendBlocks(buffer, buf_size);
			break;
		}
		case CommandList::GetHashAll:
		{
			SolverGetHashAll();
			break;
		}
		case CommandList::SendHash:
		{
			SolverSendHash(buffer, buf_size, ip_buffer, ip_size);
			break;
		}
		case CommandList::SendIpTable:
		{
			GenTableRegistrationLevelNode(buffer, (buf_size-1));
			break;
		}
		case CommandList::SendTransaction:
		{
			if (DefiningNode_ != LevelNodes::Main)
			{
				SolverSendTransaction(buffer, buf_size);
			}
			break;
		}
		case CommandList::SendTransactionList:
		{
			SolverSendTransactionList(buffer, buf_size);
			break;
		}
		case CommandList::SendVector:
		{
			SolverSendVector(buffer, buf_size);
			break;
		}
		case CommandList::SendMatrix:
		{
			SolverSendMatrix(buffer, buf_size);
			break;
		}
		case CommandList::GiveHash2:
		{
			break;
		}
		case CommandList::SuperCommand:
		{
			SuperCommandAAA(buffer, buf_size);
			break;
		}
		case CommandList::SendSync:
		{
			SendSync1(buffer, buf_size, ip_buffer, ip_size);
			break;
		}
		case CommandList::SendFirstBlock:
		{
			break;
		}
		default:
		{
			break;
		}
	}
}



SessionIO::~SessionIO()
{

}

void SessionIO::StartReceive()
{
	if (!MyPublicKey_.empty())
	{
		InputServiceSocket_->async_receive_from(
				boost::asio::buffer(&RecvBuffer, sizeof(RecvBuffer)), InputServiceSendEndpoint_,
				boost::bind(&SessionIO::InputServiceHandleReceive, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		if (OneReg)
		{
			std::cout << "Connect... " << std::endl;
			RegistrationToServer();
		}
	}
	else
	{
		std::cout << "Please entry public key in file ""PublicKey.txt"" " << std::endl;
	}
}

void SessionIO::InitMap()
{

}

void SessionIO::InputServiceHandleReceive(const boost::system::error_code & error, std::size_t bytes_transferred)
{
	if (!error)
	{
		if (OneReg)
		{
			if (RecvBuffer.command == CommandList::Registration)
			{
				std::cout << "Connect... OK" << std::endl;			
				OneReg = false;

				if(RecvBuffer.subcommand == SubCommandList::RegistrationLevelNode)
				{
					InRegistrationLevelNodeWithRings(bytes_transferred);
				}
				
				InRegistrationNode();

				StartReceive();
				return;
			}
			else
			{
				std::cout << "Connect... NO" << std::endl;
				StartReceive();
				return;
			}
		}

		InRegistrationNode();

		switch (RecvBuffer.command)
		{
			case CommandList::Redirect:
			{
				if (!RunRedirect(bytes_transferred))
				{
					StartReceive();
					return;
				}
				else
				{	
					switch (RecvBuffer.subcommand)
					{
						case SubCommandList::RegistrationLevelNode:
						{	
							InRegistrationLevelNodeWithRings(bytes_transferred);
							break;
						}
						case SubCommandList::GetBlock:
						{
							if (DefiningNode_ == LevelNodes::Normal)
							{

							}
							break;
						}
						case  SubCommandList::GetBlocks:
						{
							GetBlocks2(bytes_transferred);
							break;
						}
						case  SubCommandList::GetFirstBlock:
						{
							break;
						}
						case SubCommandList::SGetTransaction:
						{
							if (DefiningNode_ == LevelNodes::Main)
							{

							}
							break;
						}
						case SubCommandList::SGetTransactionsList:
						{
							if (DefiningNode_ == LevelNodes::Ñonfidant)
							{

							}
							break;
						}
						case SubCommandList::SGetVector:
						{
							if (DefiningNode_ == LevelNodes::Ñonfidant)
							{

							}
							break;
						}
						case SubCommandList::SGetMatrix:
						{
							if (DefiningNode_ == LevelNodes::Ñonfidant)
							{

							}
							break;
						}
						case SubCommandList::SGetHash:
						{
							if (DefiningNode_ == LevelNodes::Write)
							{

							}
							break;
						}
						default:
						{
							break;
						}
					}
				}
				break;
			}
			case CommandList::GetHash:
			{
				if (DefiningNode_ == LevelNodes::Write)
				{

					
				}
				break;
			}
			case CommandList::GetMatrix:
			{
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{

				}
				break;
			}
			case CommandList::GetTransaction:
			{
				if (DefiningNode_ == LevelNodes::Main)
				{

				}
				break;
			}
			case CommandList::GetTransactionList:
			{
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{

				}
				break;
			}
			case CommandList::GetVector:
			{
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
		
				}
				break;
			}
			case CommandList::GetSync:
				
				if (DefiningNode_ == LevelNodes::Main) {
				
				}
				break;
			case CommandList::RealBlock:
				
				if (DefiningNode_ == LevelNodes::Write) {
					
				}
				break;
	
			default:
			{
			
				break;
			}
		}
	}
	else
	{
		
	}
	
	StartReceive();
}

std::string SessionIO::getMessageHash(const std::string& publicKey, const char* data, unsigned int size_data) {
	const std::string dataStr(data, size_data);

	std::ostringstream ss;
	ss << lastMessageId;
	
	return GenHashBlock((ss.str() + publicKey + " " + dataStr).c_str(), size_data + publicKey.size() + 1);
}

void SessionIO::outFrmPack(CommandList cmd, SubCommandList sub_cmd, Version ver,
						   const char * data, unsigned int size_data)
{
	std::string hash_buff;
	unsigned int count = 0;


	if (size_data > max_length)
	{
		count = size_data % max_length;
		SendBuffer.countHeader = size_data / max_length;
		if (count != NULL)
			SendBuffer.countHeader++;
	}


	if (data != NULL && size_data != NULL)
	{
		hash_buff = getMessageHash(MyPublicKey_, data, size_data);
	}

	memcpy(SendBuffer.origin_ip, myIp.c_str(), myIp.size());
	SendBuffer.origin_ip[myIp.size()] = '\0';

	SendBuffer.command = cmd;
	SendBuffer.subcommand = sub_cmd;
	SendBuffer.version = ver;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publicKey, MyPublicKey_.c_str(), MyPublicKey_.length());

	if (size_data > max_length)
	{
		for (unsigned int i = 0; i < SendBuffer.countHeader; i++)
		{
			SendBuffer.header = i;
			if (i == SendBuffer.countHeader - 1)
			{
				memcpy(SendBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
				memcpy(SendBuffer.data, data, count);
				outSendPack(count);
			}
			else
			{
				memcpy(SendBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
				memcpy(SendBuffer.data, data, max_length);
				outSendPack(max_length);
				data += max_length;
			}
		}
	}
	else
	{
		SendBuffer.header = 0;
		SendBuffer.countHeader = 0;
		if(!data == NULL)
		memcpy(SendBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());

		if (!data == NULL)
			memcpy(SendBuffer.data, data, size_data);
		outSendPack(size_data);


	}
}

void SessionIO::outSendPack(unsigned int size_pck)
{
	boost::shared_ptr<std::string> message;
	message = boost::shared_ptr<std::string>(new std::string);
	message->append(reinterpret_cast<const char*>(&SendBuffer), SizePacketHeader2 + size_pck);

	OutputServiceSocket_->async_send_to(boost::asio::buffer(*message), OutputServiceSendEndpoint_,
		boost::bind(&SessionIO::outputHandleSend, this, message,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}

void SessionIO::outputHandleSend(boost::shared_ptr<std::string> message,
	const boost::system::error_code& error,
	std::size_t bytes_transferred)
{
	if (!error)
	{

	}
	else
	{

	}
}

void SessionIO::inFrmPack(CommandList cmd, SubCommandList sub_cmd, Version ver,
						  const char * data, unsigned int size_data, std::string hash_buff)
{

	unsigned int count = 0;

	if (size_data > max_length)
	{
		count = size_data % max_length;
		RecvBuffer.countHeader = size_data / max_length;   
		if (count != NULL)
			RecvBuffer.countHeader++;
	}

	if(hash_buff.empty() && data != NULL && size_data != NULL)
	{ 
		hash_buff = getMessageHash(MyPublicKey_, data, size_data);
		memcpy(RecvBuffer.origin_ip, myIp.c_str(), myIp.size());
		RecvBuffer.origin_ip[myIp.size()] = '\0';
	}
	
	RecvBuffer.command		= cmd;
	RecvBuffer.subcommand	= sub_cmd;
	RecvBuffer.version		= ver;
	memcpy(RecvBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(RecvBuffer.publicKey, MyPublicKey_.c_str(), MyPublicKey_.length());



	if (size_data > max_length)
	{
		for (unsigned int i = 0; i < RecvBuffer.countHeader; i++)
		{

			RecvBuffer.header = i;
			if (i == RecvBuffer.countHeader - 1)
			{

				memcpy(RecvBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
				memcpy(RecvBuffer.data, data, count);
				inSendPack(count);
			}
			else
			{

				memcpy(RecvBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
				memcpy(RecvBuffer.data, data, max_length);
				inSendPack(max_length);
				data += max_length;
			}
		}
	}
	else
	{

		RecvBuffer.header = NULL;
		RecvBuffer.countHeader = NULL;

		if(!(data == NULL))
		{ 

			memcpy(RecvBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
		}
		if (!(data == NULL))
			memcpy(RecvBuffer.data, data, size_data);
		
		inSendPack(size_data);
	}

}

void SessionIO::inSendPack(unsigned int size_pck)
{
	boost::shared_ptr<std::string> message;
	message = boost::shared_ptr<std::string>(new std::string);
	message->append(reinterpret_cast<const char*>(&RecvBuffer), SizePacketHeader2 + size_pck);

	InputServiceSocket_->async_send_to(boost::asio::buffer(*message), InputServiceSendEndpoint_,
			boost::bind(&SessionIO::inputHandleSend, this, message,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}

void SessionIO::inputHandleSend(boost::shared_ptr<std::string> message,
	const boost::system::error_code& error,
	std::size_t bytes_transferred)
{
	if (!error)
	{

	}
	else
	{

	}
}



void SessionIO::RegistrationToServer()
{
	OutputServiceSendEndpoint_ = OutputServiceServerEndpoint_;
	outFrmPack(CommandList::Registration, SubCommandList::Empty, Version::version_1, MyPublicKey_.c_str(), MyPublicKey_.size());
}

void SessionIO::SendSync1(const char * data, unsigned int size_data, const char * ip, unsigned int size_ip)
{
	std::string ip_buff;
	ip_buff.append(ip, size_ip);
	udp::resolver::query query_send(udp::v4(), ip_buff.c_str(), host_port_);
	InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	inFrmPack(CommandList::RealBlock, SubCommandList::Empty , Version::version_1, data, size_data);  
}

void SessionIO::SendBlocks(const char * buff, unsigned int size)
{
	inFrmPack(CommandList::Redirect, SubCommandList::GetBlocks, Version::version_1, buff, size);  
}

void SessionIO::SendBlocks2(const char * buff, unsigned int size)
{
	inFrmPack(CommandList::Redirect, SubCommandList::GetFirstBlock, Version::version_1, buff, size);  
}

void SessionIO::GetBlocks2(std::size_t bytes_transferred)
{ 
	
}

void SessionIO::SuperCommandAAA(char * data, unsigned int size_data)
{
	udp::resolver::query query_send(udp::v4(), GeneralNode_.c_str(), host_port_);
	InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	inFrmPack(CommandList::GetSync, SubCommandList::Empty, Version::version_1, data, size_data);  //!!
}

void SessionIO::SuperCommandSSS(char * data, unsigned int size_data)
{

}

void SessionIO::SendSinhroPacket()
{
	OutputServiceSendEndpoint_ = OutputServiceServerEndpoint_;
	outFrmPack(CommandList::SinhroPacket, SubCommandList::Empty, Version::version_1, MyPublicKey_.c_str(), MyPublicKey_.length());
}

std::vector<SessionIO::PacketNode> SessionIO::parsePacketNodes(const std::string& nodesStr) {
	std::vector<SessionIO::PacketNode> result;

	std::vector<std::string> nodes;

	{
		const char* start = nodesStr.c_str();
		const char* ptr = start;
		const char* end = ptr + nodesStr.size();
		while (ptr != end) {
			if (*ptr == '|') {
				nodes.emplace_back(start, ptr);
				start = ptr + 1;
			}
			++ptr;
		}
	}

	for (auto& n : nodes) {
		std::vector<std::string> values;

		const size_t size_array = n.size() + 1;
		char* c_string = new char[size_array];
		memcpy(c_string, n.c_str(), n.size());
		c_string[n.size()] = '*';

		const char* start = c_string;
		const char* ptr = start;
		const char* end = ptr + size_array;
		while (ptr != end) {
			if (*ptr == '*') {
				values.emplace_back(start, ptr);
				start = ptr + 1;
			}
			++ptr;
		}

		if (values.size() != 4) {
			std::cerr << "!!! Expected structure, got shit: " << n << std::endl;
			continue;
		}

		SessionIO::PacketNode pn;
		pn.ip = values[0];
		pn.port = values[1];
		pn.hash = values[2];
		pn.key = values[3];

		result.push_back(pn);
	}

	return result;
}

void SessionIO::InRegistrationLevelNodeWithRings(std::size_t bytes_transferred)
{
	ÑonfidantNodes_.clear();
	GeneralNode_.clear();

	std::vector<PacketNode> packNodes;

	const uint32_t TEXT_IP_MAX_LENGTH = 17;
	std::string input(RecvBuffer.data, bytes_transferred - SizePacketHeader2);
	auto firstIpEnd = input.begin() + TEXT_IP_MAX_LENGTH;

	if (input.size() < TEXT_IP_MAX_LENGTH || std::find(input.begin(), firstIpEnd, ' ') != firstIpEnd) {
		std::vector<std::string> ips;

		if (!input.empty() && input.back() != ' ')
			input.append(" ");

		const char* start = input.c_str();
		const char* ptr = start;
		const char* end = ptr + input.size();

		while (ptr != end) {
			if (*ptr == ' ') {
				SessionIO::PacketNode pn;
				pn.ip = std::string(start, ptr);
				pn.port = 9001;
				packNodes.push_back(pn);
				start = ptr + 1;
			}
			++ptr;
		}
	}
	else {
		std::string input(RecvBuffer.data, bytes_transferred - SizePacketHeader2);


		packNodes = parsePacketNodes(input);

		for (auto& pn : packNodes)
			m_nodesRing.push_back(pn);
	}

	DefiningNode_ = LevelNodes::Normal;

	if (packNodes.size() < 4) {
		return;
	}

	GeneralNode_ = packNodes[0].ip;
	for (size_t i = 1; i < 4; ++i) {
		ÑonfidantNodes_.push_back(packNodes[i].ip);

		if (packNodes[i].ip == InputServiceRecvEndpoint_.address().to_string())
			DefiningNode_ = LevelNodes::Ñonfidant;
	}

	if (GeneralNode_ == InputServiceRecvEndpoint_.address().to_string())
		DefiningNode_ = LevelNodes::Main;

	static bool flag = true;
	if (flag)
	{
		/* Test feature */
		flag = false;
		solver->setBD();
	}

	if (DefiningNode_ == LevelNodes::Normal)
	{
		
	}

	if (solver != nullptr)
	{
		

	}


	std::cout << "GeneralNode_: " << GeneralNode_ << " " << "GeneralNode_ size: " << GeneralNode_.size() << std::endl;

	for (auto & e : ÑonfidantNodes_)
	{
		std::cout << "ÑonfidantNodes_: " << e << " " << "ÑonfidantNodes_ size: " << e.size() << std::endl;
	}
}

const unsigned MAX_REDIRECT = 5;

/* Returns true if further processing needed */
bool SessionIO::RunRedirect(std::size_t bytes_transferred)
{


	Storage check;
	memcpy(check.HashBlock, RecvBuffer.HashBlock, sizeof(check.HashBlock));
	check.header = RecvBuffer.header;

	auto myPack = std::find_if(BackData_.begin(), BackData_.end(), [&check](auto& lhs) { return lhs.first == check; });
	const bool needProcessing = (myPack == BackData_.end());

	if (!needProcessing) {
		if (myPack->second == MAX_REDIRECT) return false;
		++(myPack->second);
	}
	else
		BackData_.push_back(std::make_pair(check, 1));

	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty() && e.ip != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, static_cast<SubCommandList>(RecvBuffer.subcommand), Version::version_1, NULL, bytes_transferred - SizePacketHeader2, std::string(RecvBuffer.HashBlock, sizeof(RecvBuffer.HashBlock)));
		}
	}

	SendSinhroPacket();

	return needProcessing;
}

const unsigned MAX_TIMES_NODE_IN_BUF = 30;

void SessionIO::InRegistrationNode()
{
	if (RecvBuffer.command == CommandList::Registration)
	{
		ServerHash_.append((char*)RecvBuffer.hash, hash_length);
		ServerKey_.append((char*)RecvBuffer.publicKey, publicKey_length);
	}
	PacketNode RegistrationNode;
	RegistrationNode.hash.append((char*)RecvBuffer.hash, hash_length);
	RegistrationNode.key.append((char*)RecvBuffer.publicKey, publicKey_length);
	RegistrationNode.ip = InputServiceSendEndpoint_.address().to_string();

	if (ServerHash_ == RegistrationNode.hash)
		RegistrationNode.port = server_port_;
	else
		RegistrationNode.port = host_port_;

	unsigned times = 0;

	for (auto& e : m_nodesRing) {
		if (e.ip == RegistrationNode.ip && e.port == RegistrationNode.port) {
			++times;
			if (times == MAX_TIMES_NODE_IN_BUF) {
				return;
			}
		}
	}

	m_nodesRing.push_back(RegistrationNode);
}



void SessionIO::InRegistrationLevelNode(std::size_t bytes_transferred)
{
		ÑonfidantNodes_.clear();
		GeneralNode_.clear();
		std::string buffer1(" ");
		std::string buffer2;
		buffer2.append((char*)RecvBuffer.data, bytes_transferred - SizePacketHeader2 );

		static bool flag = true;
		if (flag)
		{
			flag = false;
			solver->setBD();
		}

		DefiningNode_ = LevelNodes::Normal;

		for (unsigned int i = 0; !buffer1.empty(); i++)
		{
			buffer1 = _text_help::get_field_from_st(buffer2, ' ', i);
			if (i >= 1 && !buffer1.empty())
			{

				ÑonfidantNodes_.push_back(buffer1);

				if (buffer1 == InputServiceRecvEndpoint_.address().to_string())
				{
					DefiningNode_ = LevelNodes::Ñonfidant;
				}
			}
			else if (!buffer1.empty() && i == 0)
			{
				GeneralNode_ = buffer1;

				if (GeneralNode_ == InputServiceRecvEndpoint_.address().to_string())
				{
					DefiningNode_ = LevelNodes::Main;
				}
			}
		}
		if (DefiningNode_ == LevelNodes::Normal)
		{
			

		}

		if (solver != nullptr)
		{

		}


	std::cout << "GeneralNode_: " << GeneralNode_ << " "  << "GeneralNode_ size: " << GeneralNode_ .size()<< std::endl;

	for(auto & e : ÑonfidantNodes_)
	{
		std::cout << "ÑonfidantNodes_: " << e  << " " << "ÑonfidantNodes_ size: " << e.size() <<  std::endl;
	}
}

void SessionIO::SolverSendHash(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size)
{


	++lastMessageId;

	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::SGetHash, Version::version_1, buffer, buf_size);  //!!
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverGetHashAll()
{
	++lastMessageId;
	static unsigned int size_ip_addr = InputServiceRecvEndpoint_.address().to_string().length();
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::GiveHash, Version::version_1,
					  InputServiceRecvEndpoint_.address().to_string().c_str(), size_ip_addr);  //!!
		}
	}
	SendSinhroPacket();
}

void SessionIO::GenTableRegistrationLevelNode(char* data, unsigned size)
{
	++lastMessageId;
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::RegistrationLevelNode, Version::version_1, data, size);  //!!
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendBlock(const char * data, unsigned size)
{
	++lastMessageId;
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::GetBlock, Version::version_1, data, size); //!
		}
	}

	SendSinhroPacket();
}

void SessionIO::SolverSendTransaction(const char * data, unsigned size)
{

	++lastMessageId;
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty() && e.ip != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_sends(udp::v4(), e.ip, e.port);
			OutputServiceSendEndpoint_ = *InputServiceResolver_.resolve(query_sends);
			outFrmPack(CommandList::Redirect, SubCommandList::SGetTransaction, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendTransactionList(const char * data, unsigned size)
{

	++lastMessageId;
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty() && e.ip != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::SGetTransactionsList, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendVector(const char * data, unsigned size)
{

	++lastMessageId;
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty() && e.ip != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_sends(udp::v4(), e.ip, e.port);
			OutputServiceSendEndpoint_ = *InputServiceResolver_.resolve(query_sends);
			outFrmPack(CommandList::Redirect, SubCommandList::SGetVector, Version::version_1, data, size);
		}
	}

	SendSinhroPacket();
}

void SessionIO::SolverSendMatrix(const char * data, unsigned size)
{

	++lastMessageId;
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty() && e.ip != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_sends(udp::v4(), e.ip, e.port);
			OutputServiceSendEndpoint_ = *InputServiceResolver_.resolve(query_sends);
			outFrmPack(CommandList::Redirect, SubCommandList::SGetMatrix, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::GenerationHash()
{
	char buff[45];

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_real_distribution<> dis1(-100000, 100000);
	SHA1 hash;
	char Hex[32];
	itoa(dis1(gen), Hex, 32);
	hash.update(Hex);
	MyHash_ = hash.final();

	std::string tmp(24, '0');
	MyPublicKey_ = tmp;
	
	std::ifstream fin("PublicKey.txt");
	if (!fin.is_open())
		std::cout << "File is not open!\n";
	else
	{
		fin.getline(buff, 45);
		tmp = this->GenHashBlock(buff, 44);
		MyPublicKey_ += tmp;
	
		fin.close();
	}

}

const std::string SessionIO::GenHashBlock(const char * buff, unsigned int size)
{
	SHA1 sha_1;
	sha_1.update(std::string(buff, size));
	return sha_1.final();
}

void SessionIO::Run()
{
	StartReceive();
	io_service_server_.run();
}

unsigned int  SessionIO::ñalcSumHeader() const
{
	return sizeof(RecvBuffer) - max_length;
}
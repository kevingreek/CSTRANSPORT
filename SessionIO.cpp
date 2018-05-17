#include <sstream>
#include <vector>
#include <thread>
#include <random>
#include <fstream>

#include "SessionIO.hpp"
#include "TextHelp.hpp"

#include "sha1.hpp"
//#include <Solver\Fake\Fake_Solver.hpp>

bool SessionIO::OneReg = true;

char g_buff[200000] = { 0 };

using namespace std::placeholders;
SessionIO::SessionIO() : InputServiceResolver_(io_service_server_), OutputServiceResolver_(io_service_client_) 
						/*factory(),solver(nullptr),*/ 
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
	boost::asio::ip::udp::socket::receive_buffer_size recvBuff(65536);
	InputServiceSocket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	InputServiceSocket_->set_option(recvBuff);

	InputServiceSocket_->get_option(recvBuff);

	const boost::property_tree::ptree & host_Output = config.get_child("hostOutput");
	udp::resolver::query query_recv(udp::v4(), host_Output.get<std::string>("ip"), host_Output.get<std::string>("port", "9000"));
	OutputServiceRecvEndpoint_ = *OutputServiceResolver_.resolve(query_recv);
	OutputServiceSocket_ = new udp::socket(io_service_client_, OutputServiceRecvEndpoint_);
	boost::asio::ip::udp::socket::send_buffer_size sendBuff(65536);
	OutputServiceSocket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	InputServiceSocket_->set_option(sendBuff);

	const boost::property_tree::ptree & server = config.get_child("server");
	udp::resolver::query query_serv(udp::v4(), server.get<std::string>("ip"), server.get<std::string>("port", "6000"));
	OutputServiceServerEndpoint_ = *OutputServiceResolver_.resolve(query_serv);

	m_nodesRing.resize(100);
	BackData_.resize(100);

	DefiningNode_ = LevelNodes::Normal;
	GenerationHash();

	SizePacketHeader = ñalcSumHeader();
	SizePacketHeader2 = ñalcSumHeader();

	//std::cout << "Size SizePacketHeader2: " << SizePacketHeader2 << std::endl;
	//std::cout << "Sizeof pack: " << sizeof(Packet) << std::endl;


	//solver = factory.createSolver(Credits::solver_type::fake,MyPublicKey_, 
	//						InputServiceRecvEndpoint_.address().to_string());
	//
	//if (solver != nullptr) {
	//	solver->createBD();
	//	solver->initApi();
	//}


	//SolverSendData_ = std::bind(&SessionIO::SolverSendData, this
	//	, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
	//
	//solver->register_callback_send(SolverSendData_);
	//
	//solver->register_callback_node_type([this](int value) {
	//	if (this->DefiningNode_ == LevelNodes::Ñonfidant) {
	//		this->DefiningNode_ = LevelNodes::Write;

	//	}
	//});
	//
	//solver->register_callback_get_nodes_ip([this](void) {
	//	return this->ÑonfidantNodes_;
	//});

	 
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
			//std::cout << "Run SendBlock" << std::endl;
			if (DefiningNode_ == LevelNodes::Write)
			{
				SendBlocks(buffer, buf_size);
			}
			break;
		}
		case CommandList::GetHashAll:
		{
			//std::cout << "Run GetHashAll" << std::endl;
			SolverGetHashAll();
			break;
		}
		case CommandList::SendHash:
		{
			//std::cout << "Run SendHash" << std::endl;
			SolverSendHash(buffer, buf_size, ip_buffer, ip_size);
			break;
		}
		case CommandList::SendIpTable:
		{
			//std::cout << "Run SendIpTable" << std::endl;
			GenTableRegistrationLevelNode(buffer, buf_size);
			break;
		}
		case CommandList::SendTransaction:
		{
			//std::cout << "Run SendTransaction" << std::endl;
			if (DefiningNode_ != LevelNodes::Main)
			{
				SolverSendTransaction(buffer, buf_size);
			}
			break;
		}
		case CommandList::SendTransactionList:
		{
			//std::cout << "Run SendTransactionList" << std::endl;
			SolverSendTransactionList(buffer, buf_size);
			break;
		}
		case CommandList::SendVector:
		{
			//std::cout << "Run SendVector" << std::endl;
			SolverSendVector(buffer, buf_size);
			break;
		}
		case CommandList::SendMatrix:
		{
			//std::cout << "Run SendMatrix" << std::endl;
			SolverSendMatrix(buffer, buf_size);
			break;
		}
		case CommandList::GiveHash2:
		{
			//std::cout << "Run GiveHash2" << std::endl;
			break;
		}
		default:
		{
		//	std::cout << "Incorrect command" << std::endl;
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
	//std::cout << "InputServiceHandleReceive RecvBuffer.command: " << (unsigned int)RecvBuffer.command << std::endl;
	//std::cout << "InputServiceHandleReceive RecvBuffer.subcommand: " << (unsigned int)RecvBuffer.subcommand << std::endl;
	//std::cout << "InputServiceHandleReceive RecvBuffer.version: " << (unsigned int)RecvBuffer.version << std::endl;

	//std::cout << "InputServiceHandleReceive RecvBuffer.hash: ";
	//for (unsigned int i = 0; i < 40; i++)
	//{
	//	std::cout << RecvBuffer.hash[i];
	//}
	//std::cout << std::endl;

	//std::cout << "InputServiceHandleReceive RecvBuffer.publicKey: ";
	//for (unsigned int i = 0; i < 256; i++)
	//{
	//	std::cout << RecvBuffer.publicKey[i];
	//}
	//std::cout << std::endl;

	//std::cout << "InputServiceHandleReceive RecvBuffer.HashBlock: ";
	//for (unsigned int i = 0; i < 40; i++)
	//{
	//	std::cout << RecvBuffer.HashBlock[i];
	//}
	//std::cout << std::endl;

	//std::cout << "InputServiceHandleReceive RecvBuffer.header: " << (unsigned int)RecvBuffer.header << std::endl;
	//std::cout << "InputServiceHandleReceive RecvBuffer.countHeader: " << (unsigned int)RecvBuffer.countHeader << std::endl;


	if (!error)
	{
		if (OneReg)
		{
			if (RecvBuffer.command == CommandList::Registration)
			{
				std::cout << "Connect... OK" << std::endl;			
				OneReg = false;
				InRegistrationNode();

				if (RecvBuffer.version == 10)
				{
					//solver->setBD();
				}

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
					//std::cout << "Run Redirect OK" << std::endl;
					switch (RecvBuffer.subcommand)
					{
						case SubCommandList::RegistrationLevelNode:
						{
						//	std::cout << "Run SelectionProcess" << std::endl;	
							InRegistrationLevelNode(bytes_transferred);
							break;
						}
						case SubCommandList::GetBlock:
						{
							//std::cout << "Run GetBlock" << std::endl;
							if (DefiningNode_ == LevelNodes::Normal)
							{
								GetBlocks2(bytes_transferred);
							}
							break;
						}
						case  SubCommandList::GetBlocks:
						{
							//std::cout << "Run GetBlock !!S!!" << std::endl;
							GetBlocks2(bytes_transferred);
							break;
						}
						default:
						{
						//	std::cout << "Incorrect subcommand" << std::endl;
							break;
						}
					}
				}
				break;
			}
			case CommandList::GetHash:
			{
				//std::cout << "Run GetHash" << std::endl;
				if (DefiningNode_ == LevelNodes::Write)
				{
					//std::random_shuffle(this->ÑonfidantNodes_.begin(), this->ÑonfidantNodes_.end());
					//solver->getHash(RecvBuffer.data, bytes_transferred - SizePacketHeader, InputServiceSendEndpoint_.address().to_string().c_str(), InputServiceSendEndpoint_.address().to_string().length(), this->ÑonfidantNodes_);
					
				}
				break;
			}
			case CommandList::GetMatrix:
			{
				//std::cout << "Run GetMatrix" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
					
				//	solver->getMatrix(RecvBuffer.data, bytes_transferred - SizePacketHeader, (void*)InputServiceSendEndpoint_.address().to_string().c_str(), InputServiceSendEndpoint_.address().to_string().length(),ÑonfidantNodes_);
				}
				break;
			}
			case CommandList::GetTransaction:
			{
				//std::cout << "Run GetTransaction" << std::endl;
				if (DefiningNode_ == LevelNodes::Main)
				{
				//	solver->getTransaction(RecvBuffer.data, bytes_transferred - SizePacketHeader);
				}
				break;
			}
			case CommandList::GetTransactionList:
			{
				//std::cout << "Run GetTransactionList" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
				//	solver->getTransactionList(RecvBuffer.data, bytes_transferred - SizePacketHeader);
				}
				break;
			}
			case CommandList::GetVector:
			{
				//std::cout << "Run GetVector" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
				//	solver->getVector(RecvBuffer.data, bytes_transferred - SizePacketHeader, (void*)InputServiceSendEndpoint_.address().to_string().c_str(), InputServiceSendEndpoint_.address().to_string().length());
				}
				break;
			}
			default:
			{
				std::cout << "Incorrect command" << std::endl;
				break;
			}
		}
	}
	else
	{
		
	}
	
	StartReceive();
}

void SessionIO::outFrmPack(CommandList cmd, SubCommandList sub_cmd, Version ver,
						   const char * data, unsigned int size_data)
{
	std::string hash_buff;
	unsigned int count = size_data % max_length;
	SendBuffer.countHeader = size_data / max_length;
	if (count != NULL)
		SendBuffer.countHeader++;
	if (data != NULL && size_data != NULL)
	hash_buff = GenHashBlock(data, size_data);
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
				//hash_buff = GenHashBlock(data, count);
				memcpy(SendBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
				memcpy(SendBuffer.data, data, count);
				outSendPack(count);
			}
			else
			{
				//hash_buff = GenHashBlock(data, size_data - i);
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
		//hash_buff = GenHashBlock(data, count);
		memcpy(SendBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());

		if (!data == NULL)
			memcpy(SendBuffer.data, data, size_data);
		outSendPack(size_data);
	}

	//std::cout << "outFrmPack SendBuffer.command: " << (unsigned int)SendBuffer.command << std::endl;
	//std::cout << "outFrmPack SendBuffer.subcommand: " << (unsigned int)SendBuffer.subcommand << std::endl;
	//std::cout << "outFrmPack SendBuffer.version: " << (unsigned int)SendBuffer.version << std::endl;

	//std::cout << "outFrmPack SendBuffer.hash: ";
	//for (unsigned int i = 0; i < 40; i++)
	//{
	//	std::cout << SendBuffer.hash[i];
	//}
	//std::cout << std::endl;

	//std::cout << "outFrmPack SendBuffer.publicKey: ";
	//for (unsigned int i = 0; i < 256; i++)
	//{
	//	std::cout << SendBuffer.publicKey[i];
	//}
	//std::cout << std::endl;

	//std::cout << "outFrmPack SendBuffer.HashBlock: ";
	//for (unsigned int i = 0; i < 40; i++)
	//{
	//	std::cout << SendBuffer.HashBlock[i];
	//}
	//std::cout << std::endl;

	//std::cout << "outFrmPack SendBuffer.header: " <<	  (unsigned int)SendBuffer.header << std::endl;
	//std::cout << "outFrmPack SendBuffer.countHeader: " << (unsigned int)SendBuffer.countHeader << std::endl;

}

void SessionIO::outSendPack(unsigned int size_pck)
{
	boost::shared_ptr<std::string> message;
	message = boost::shared_ptr<std::string>(new std::string);
	message->append(reinterpret_cast<const char*>(&SendBuffer), SizePacketHeader2 + size_pck);
	InputServiceSocket_->async_send_to(boost::asio::buffer(*message), OutputServiceSendEndpoint_,
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
						  const char * data, unsigned int size_data)
{
	std::string hash_buff;
	unsigned int count	   = size_data % max_length;
	RecvBuffer.countHeader = size_data / max_length;

	if (count != NULL)
		SendBuffer.countHeader++;
	if(data != NULL && size_data != NULL)
	hash_buff = GenHashBlock(data, size_data);
	RecvBuffer.command		= cmd;
	RecvBuffer.subcommand	= sub_cmd;
	RecvBuffer.version		= ver;
	memcpy(RecvBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(RecvBuffer.publicKey, MyPublicKey_.c_str(), MyPublicKey_.length());


	

	if (size_data > max_length)
	{
		for (unsigned int i = 0; i < SendBuffer.countHeader; i++)
		{
			SendBuffer.header = i;
			if (i == SendBuffer.countHeader - 1)
			{
				//hash_buff = GenHashBlock(data, count);
				memcpy(RecvBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
				memcpy(RecvBuffer.data, data, count);
				inSendPack(count);
			}
			else
			{
				//hash_buff = GenHashBlock(data, size_data - i);
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
		//hash_buff = GenHashBlock(data, count);
		memcpy(RecvBuffer.HashBlock, hash_buff.c_str(), hash_buff.length());
		if (!data == NULL)
			memcpy(RecvBuffer.data, data, size_data);
		inSendPack(size_data);
	}

	//std::cout << "inFrmPack RecvBuffer.command: " << (unsigned int)RecvBuffer.command << std::endl;
	//std::cout << "inFrmPack RecvBuffer.subcommand: " << (unsigned int)RecvBuffer.subcommand << std::endl;
	//std::cout << "inFrmPack RecvBuffer.version: " << (unsigned int)RecvBuffer.version << std::endl;

	//std::cout << "inFrmPack RecvBuffer.hash: ";
	//for (unsigned int i = 0; i < 40; i++)
	//{
	//	std::cout << RecvBuffer.hash[i];
	//}
	//std::cout << std::endl;

	//std::cout << "inFrmPack RecvBuffer.publicKey: ";
	//for (unsigned int i = 0; i < 256; i++)
	//{
	//	std::cout << RecvBuffer.publicKey[i];
	//}
	//std::cout << std::endl;

	//std::cout << "inFrmPack RecvBuffer.HashBlock: ";
	//for (unsigned int i = 0; i < 40; i++)
	//{
	//	std::cout << RecvBuffer.HashBlock[i];
	//}
	//std::cout << std::endl;

	//std::cout << "inFrmPack RecvBuffer.header: " << (unsigned int)RecvBuffer.header << std::endl;
	//std::cout << "inFrmPack RecvBuffer.countHeader: " << (unsigned int)RecvBuffer.countHeader << std::endl;
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

void SessionIO::SendBlocks(const char * buff, unsigned int size)
{
	inFrmPack(CommandList::Redirect, SubCommandList::GetBlocks, Version::version_1, buff, size);
}

void SessionIO::GetBlocks2(std::size_t bytes_transferred)
{ 
	//solver->getBlock(RecvBuffer.data, bytes_transferred - SizePacketHeader);
}

void SessionIO::SendSinhroPacket()
{
	OutputServiceSendEndpoint_ = OutputServiceServerEndpoint_;
	outFrmPack(CommandList::SinhroPacket, SubCommandList::Empty, Version::version_1, MyPublicKey_.c_str(), MyPublicKey_.length());
}

bool SessionIO::RunRedirect(std::size_t bytes_transferred)
{
	Storage check;
	memcpy(check.HashBlock, RecvBuffer.HashBlock, sizeof(check.HashBlock));
	check.header = RecvBuffer.header;

	for (auto & e : BackData_)
		if (e == check)
			return false;

	BackData_.push_back(check);

	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty() && e.ip != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, static_cast<SubCommandList>(RecvBuffer.subcommand), Version::version_1, NULL, bytes_transferred - SizePacketHeader2);
		}
	}
	SendSinhroPacket();
	return true;
}

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
	m_nodesRing.push_back(RegistrationNode);
}

void SessionIO::InRegistrationLevelNode(std::size_t bytes_transferred)
{
	ÑonfidantNodes_.clear();
	GeneralNode_.clear();
	std::string buffer1(" ");
	std::string buffer2;
	buffer2.append((char*)RecvBuffer.data, bytes_transferred - SizePacketHeader2);
	
	for(unsigned int i = 0 ; !buffer1.empty(); i++)
	{
		buffer1 = _text_help::get_field_from_st(buffer2, ' ', i);
		if ( i >= 1 && !buffer1.empty() )
		{
			ÑonfidantNodes_.push_back(buffer1);

			if (buffer1 == InputServiceRecvEndpoint_.address().to_string())
			{
				DefiningNode_ = LevelNodes::Ñonfidant;
			}
		}
		else if( !buffer1.empty() && i == 0)
		{
			GeneralNode_ = buffer1;
			if (GeneralNode_ == InputServiceRecvEndpoint_.address().to_string())
			{
				DefiningNode_ = LevelNodes::Main;
			}
		}
	}
}

void SessionIO::SolverSendHash(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size)
{
	std::string buff_ip;
	udp::resolver::query query_send(udp::v4(), buff_ip, host_port_);
	InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	inFrmPack(CommandList::GetHash, SubCommandList::Empty, Version::version_1, buffer, buf_size);
	SendSinhroPacket();
}

void SessionIO::SolverGetHashAll()
{
	static unsigned int size_ip_addr = InputServiceRecvEndpoint_.address().to_string().length();
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::GiveHash, Version::version_1,
					  InputServiceRecvEndpoint_.address().to_string().c_str(), size_ip_addr);
		}
	}
	SendSinhroPacket();
}

void SessionIO::GenTableRegistrationLevelNode(char * data, unsigned size)
{
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::RegistrationLevelNode, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendBlock(const char * data, unsigned size)
{
	for (auto & e : m_nodesRing)
	{
		if (!e.ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), e.ip, e.port);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::Redirect, SubCommandList::GetBlock, Version::version_1, data, size);
		}
	}

	SendSinhroPacket();
}

void SessionIO::SolverSendTransaction(const char * data, unsigned size)
{
	udp::resolver::query query_send(udp::v4(), GeneralNode_.c_str(), host_port_);
	OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	outFrmPack(CommandList::GetTransaction, SubCommandList::Empty, Version::version_1, data, size);
	SendSinhroPacket();
}

void SessionIO::SolverSendTransactionList(const char * data, unsigned size)
{
	for (auto & e : ÑonfidantNodes_)
	{
		if (!e.empty() && e != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), e.c_str(), host_port_);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::GetTransactionList, SubCommandList::Empty, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendVector(const char * data, unsigned size)
{
	for (auto & e : ÑonfidantNodes_)
	{
		if (!e.empty() && e != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), e.c_str(), host_port_);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::GetVector, SubCommandList::Empty, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendMatrix(const char * data, unsigned size)
{
	for (auto & e : ÑonfidantNodes_)
	{
		if (!e.empty() && e != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), e.c_str(), host_port_);
			InputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			inFrmPack(CommandList::GetMatrix, SubCommandList::Empty, Version::version_1, data, size);
		}
	}
	SendSinhroPacket();
}

void SessionIO::GenerationHash()
{
	char buff[256];

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_real_distribution<> dis1(-100000, 100000);
	SHA1 hash;
	char Hex[32];
	itoa(dis1(gen), Hex, 32);
	hash.update(Hex);
	MyHash_ = hash.final();

	std::ifstream fin("PublicKey.txt");
	if (!fin.is_open())
		std::cout << "File is not open!\n";
	else
	{
		fin.getline(buff, 256);
		MyPublicKey_ = buff;
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
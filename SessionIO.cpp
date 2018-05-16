#include <sstream>
#include <vector>
#include <thread>
#include <random>
#include <fstream>

#include "SessionIO.hpp"
#include "TextHelp.hpp"

#include "sha1.hpp"


bool SessionIO::OneReg = true;

using namespace std::placeholders;
SessionIO::SessionIO() : InputServiceResolver_(io_service_server_), OutputServiceResolver_(io_service_client_) ,
						SizePacketHeader(CalcSum())
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

	NodesRing_.resize(100);
	BackData_.resize(100);

	DefiningNode_ = LevelNodes::Normal;
	GenerationHash();
 
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
	if (RecvBuffer.subcommand == RegistrationLevelNode)
	{

	}
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
					switch (RecvBuffer.subcommand)
					{
						case SubCommandList::RegistrationLevelNode:
						{
							//std::cout << "Run SelectionProcess" << std::endl;	
							InRegistrationLevelNode(bytes_transferred);
							break;
						}
						case SubCommandList::GiveHash:
						{
							//std::cout << "Run GiveHash" << std::endl;
							SolverGiveHash(bytes_transferred);
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
							std::cout << "Incorrect subcommand" << std::endl;
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
				
					
				}
				break;
			}
			case CommandList::GetMatrix:
			{
				//std::cout << "Run GetMatrix" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
					
					
				}
				break;
			}
			case CommandList::GetTransaction:
			{
				//std::cout << "Run GetTransaction" << std::endl;
				if (DefiningNode_ == LevelNodes::Main)
				{
					
				}
				break;
			}
			case CommandList::GetTransactionList:
			{
				//std::cout << "Run GetTransactionList" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
					
				}
				break;
			}
			case CommandList::GetVector:
			{
				//std::cout << "Run GetVector" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
					
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

void SessionIO::InputServiceHandleSend(const boost::system::error_code & error, std::size_t bytes_transferred)
{
	if (!error)
	{

	}
	else
	{
		std::cerr << "Error sending information: " << error.message() << std::endl;
	}
}


void SessionIO::OutputServiceSendCommand(const Packet & pack, unsigned int lenData)
{
	boost::shared_ptr<std::string> message;
	message = boost::shared_ptr<std::string>(new std::string);
	message->append((char*)&pack, lenData);

	OutputServiceSocket_->async_send_to(boost::asio::buffer(*message), OutputServiceSendEndpoint_,
		boost::bind(&SessionIO::handle_send, this, message,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}

void SessionIO::handle_send(boost::shared_ptr<std::string> message,
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


void SessionIO::OutputServiceHandleSend(const boost::system::error_code& error, std::size_t bytes_transferred)
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
	if (OneReg)
	{
		SendBuffer.command = CommandList::Registration;
		SendBuffer.subcommand = 0;
		SendBuffer.version = version_;
		SendBuffer.header = 0;
		SendBuffer.countHeader = 0;
		memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
		memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
		SendBuffer.data[0] = '\0';
		OutputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, SizePacketHeader), OutputServiceServerEndpoint_,
				boost::bind(&SessionIO::InputServiceHandleSend, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		//boost::this_thread::sleep_for(boost::chrono::milliseconds(3000));
		//RegistrationToServer();
	}
}

void SessionIO::SendBlocks(const char * buff, unsigned int size)
{
	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::GetBlocks;
	SendBuffer.version = version_;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	GenHashBlock(buff, size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	
	if (size > max_length)
	{	
		unsigned int count = size % max_length;
		SendBuffer.countHeader = size / max_length;
		if (count != 0)
		{
			SendBuffer.countHeader++;
		}
		for (unsigned int i = 0; i < SendBuffer.countHeader; i++)
		{
			SendBuffer.header = i;
			if (i == SendBuffer.countHeader - 1)
			{
				memcpy(SendBuffer.data, buff, count);
				InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, count + SizePacketHeader), OutputServiceServerEndpoint_,
						boost::bind(&SessionIO::InputServiceHandleSend, this,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
			}
			else
			{
				memcpy(SendBuffer.data, buff, max_length);
				InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, max_length + SizePacketHeader), OutputServiceServerEndpoint_,
						boost::bind(&SessionIO::InputServiceHandleSend, this,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
				buff += max_length;
			}
		}
	}
	else
	{
		memcpy(SendBuffer.data, buff, size);
		SendBuffer.header = 0;
		SendBuffer.countHeader = 0;
		for (unsigned int i = 0; i < NodesRing_.size(); i++)
		{
			if (!NodesRing_[i].ip.empty())
			{
				udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
				OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
				InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
						boost::bind(&SessionIO::InputServiceHandleSend, this,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
			}
		}

	}
}

void SessionIO::GetBlocks2(std::size_t bytes_transferred)
{ 
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	tmp_hash1.clear();
	tmp_hash1.append((const char*)RecvBuffer.HashBlock, hash_length);
	if (tmp_hash1 != tmp_hash2)
	{
		tmp_hash2 = tmp_hash1;
		blocks.clear();
	}

	if (RecvBuffer.countHeader)
	{
		blocks[RecvBuffer.header].append((const char*)RecvBuffer.data, bytes_transferred);
		if (RecvBuffer.countHeader == blocks.size())
		{
			
		}
	}
	else
	{
		
	}
}

void SessionIO::SendSinhroPacket()
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::SinhroPacket;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	SendBuffer.data[0] = '\0';

	InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, SizePacketHeader), OutputServiceServerEndpoint_,
			boost::bind(&SessionIO::InputServiceHandleSend, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}


bool SessionIO::RunRedirect(std::size_t bytes_transferred)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	Storage check;
	memcpy(check.HashBlock, RecvBuffer.HashBlock, sizeof(check.HashBlock));
	check.header = RecvBuffer.header;

	for (auto & e : BackData_)
	{
		if (e == check)
		{
			return false;
		}
	}

	memcpy(&SendBuffer, &RecvBuffer, bytes_transferred);

	BackData_.push_back(check);
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			if (NodesRing_[i].ip != InputServiceRecvEndpoint_.address().to_string())
			{
				udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
				OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);

				InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, bytes_transferred /*+ 1*/), OutputServiceSendEndpoint_,
						boost::bind(&SessionIO::InputServiceHandleSend, this,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
			}
		}
	}
	return true;
}

void SessionIO::InRegistrationNode()
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	if (RecvBuffer.command == CommandList::Registration)
	{
		ServerHash_.append((char*)RecvBuffer.hash, hash_length);
		ServerKey_.append((char*)RecvBuffer.publickKey, publicKey_length);
	}
	PacketNode RegistrationNode;
	RegistrationNode.hash.append((char*)RecvBuffer.hash, hash_length);
	RegistrationNode.key.append((char*)RecvBuffer.publickKey, publicKey_length);
	RegistrationNode.ip = InputServiceSendEndpoint_.address().to_string();

	if (ServerHash_ == RegistrationNode.hash)
	{
		RegistrationNode.port = server_port_;
	}
	else
	{
		RegistrationNode.port = host_port_;
	}
	NodesRing_.push_back(RegistrationNode);
}

void SessionIO::InRegistrationLevelNode(std::size_t bytes_transferred)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	ÑonfidantNodes_.clear();
	GeneralNode_.clear();
	std::string buffer1(" ");
	std::string buffer2;
	buffer2.append((char*)RecvBuffer.data, bytes_transferred - (SizePacketHeader + 1));
	
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

void SessionIO::GenerationHash()
{
	char buff[256];

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_real_distribution<> dis1(-100000, 100000);
	std::uniform_real_distribution<> dis2(-100000, 100000);
	SHA1 hash;
	char Hex[16];
	itoa(dis1(gen), Hex, 16);
	hash.update(Hex);
	MyHash_ = hash.final();
	itoa(dis2(gen), Hex, 16);
	hash.update(Hex);
	MyHash_ = hash.final();

	std::ifstream fin("PublicKey.txt");
	if (!fin.is_open()) 
		std::cout << "File is not open!\n"; 
	else
	{
		fin.getline(buff, 256);
		MyPublicKey_ = buff;
		std::cout << MyPublicKey_ << std::endl;
		fin.close(); 
	}
	
}

void SessionIO::GenHashBlock(const char * buff, unsigned int size)
{
	std::string str;
	str.append(buff, size);
	HashBlock_.update(str);
}



void SessionIO::SolverSendHash(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	std::string buff;
	buff.append(ip_buffer, ip_size);
	SendBuffer.command = CommandList::GetHash;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(buffer, buf_size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, buffer, buf_size);
	udp::resolver::query query_send(udp::v4(), buff, host_port_);

	OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);

	InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, buf_size + SizePacketHeader /*+ 1*/), OutputServiceSendEndpoint_,
		boost::bind(&SessionIO::InputServiceHandleSend, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));

	SendSinhroPacket();

}

void SessionIO::SolverGetHashAll()
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::GiveHash;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(InputServiceRecvEndpoint_.address().to_string().c_str(), InputServiceRecvEndpoint_.address().to_string().length());
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, InputServiceRecvEndpoint_.address().to_string().c_str(), InputServiceRecvEndpoint_.address().to_string().length());
	
	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, InputServiceRecvEndpoint_.address().to_string().length() + SizePacketHeader), OutputServiceSendEndpoint_,
					boost::bind(&SessionIO::InputServiceHandleSend, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverGiveHash(std::size_t bytes_transferred)
{

}

void SessionIO::GenTableRegistrationLevelNode( char * data, unsigned size)
{
	char buff[256];

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_real_distribution<> dis1(-100000, 100000);
	std::uniform_real_distribution<> dis2(-100000, 100000);
	SHA1 hash2;
	char Hex[16];
	itoa(dis1(gen), Hex, 16);
	hash2.update(Hex);

	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::RegistrationLevelNode;
	SendBuffer.version = 0;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;

	std::string tmp2;
	tmp2 = hash2.final();

	for (unsigned int i = 0; i < 40; i++)
	{
		SendBuffer.HashBlock[i] = tmp2[i];
	}

	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
					boost::bind(&SessionIO::InputServiceHandleSend, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	} 

	SendSinhroPacket();
}

void SessionIO::SolverSendBlock(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::GetBlock;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(data, size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
				boost::bind(&SessionIO::InputServiceHandleSend, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendTransaction(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetTransaction;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(data, size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	udp::resolver::query query_send(udp::v4(), GeneralNode_.c_str(), host_port_);
	OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	OutputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
		boost::bind(&SessionIO::InputServiceHandleSend, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	SendSinhroPacket();
}

void SessionIO::SolverSendTransactionList(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetTransactionList;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(data, size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < ÑonfidantNodes_.size(); i++)
	{
		if (!ÑonfidantNodes_[i].empty() && ÑonfidantNodes_[i] != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), ÑonfidantNodes_[i].c_str(), host_port_);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
					boost::bind(&SessionIO::InputServiceHandleSend, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendVector(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetVector;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(data, size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < ÑonfidantNodes_.size(); i++)
	{
		if (!ÑonfidantNodes_[i].empty() && ÑonfidantNodes_[i] != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), ÑonfidantNodes_[i].c_str(), host_port_);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
				boost::bind(&SessionIO::InputServiceHandleSend, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	}
	SendSinhroPacket();
}

void SessionIO::SolverSendMatrix(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetMatrix;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	GenHashBlock(data, size);
	memcpy(SendBuffer.HashBlock, HashBlock_.final().c_str(), HashBlock_.final().length());
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < ÑonfidantNodes_.size(); i++)
	{
		if (!ÑonfidantNodes_[i].empty() && ÑonfidantNodes_[i] != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), ÑonfidantNodes_[i].c_str(), host_port_);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			InputServiceSocket_->async_send_to(boost::asio::buffer(&SendBuffer, size + SizePacketHeader), OutputServiceSendEndpoint_,
					boost::bind(&SessionIO::InputServiceHandleSend, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	}
	SendSinhroPacket();
}

void SessionIO::Run()
{
	StartReceive();
	io_service_server_.run();
}

constexpr std::size_t SessionIO::CalcSum() const
{
	return sizeof(RecvBuffer.command) + sizeof(RecvBuffer.subcommand) + sizeof(RecvBuffer.version) + sizeof(RecvBuffer.header) + sizeof(RecvBuffer.countHeader) +
			sizeof(RecvBuffer.hash) + sizeof(RecvBuffer.publickKey) + sizeof(RecvBuffer.HashBlock);
}
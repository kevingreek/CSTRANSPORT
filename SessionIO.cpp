#include <sstream>
#include <vector>
#include <thread>
#include <random>

#include "SessionIO.hpp"
#include "TextHelp.hpp"
#include "sha1.hpp"

bool SessionIO::OneReg = true;

using namespace std::placeholders;
SessionIO::SessionIO() : InputServiceResolver_(io_service_server_), OutputServiceResolver_(io_service_client_) ,
						timer(io_service_client_, boost::posix_time::seconds(3)),
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
	InputServiceSocket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));

	const boost::property_tree::ptree & host_Output = config.get_child("hostOutput");
	udp::resolver::query query_recv(udp::v4(), host_Output.get<std::string>("ip"), host_Output.get<std::string>("port", "9000"));
	OutputServiceRecvEndpoint_ = *OutputServiceResolver_.resolve(query_recv);
	OutputServiceSocket_ = new udp::socket(io_service_client_, OutputServiceRecvEndpoint_);
	OutputServiceSocket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));

	const boost::property_tree::ptree & server = config.get_child("server");
	udp::resolver::query query_serv(udp::v4(), server.get<std::string>("ip"), server.get<std::string>("port", "6000"));
	OutputServiceServerEndpoint_ = *OutputServiceResolver_.resolve(query_serv);

	NodesRing_.resize(100);
	BackData_.resize(10);

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
			std::cout << "Run SendBlock" << std::endl;
			if (DefiningNode_ == LevelNodes::Write)
			{

			}
			break;
		}
		case CommandList::GetHashAll:
		{
			std::cout << "Run GetHashAll" << std::endl;

			break;
		}
		case CommandList::SendHash:
		{
			std::cout << "Run SendHash" << std::endl;

			break;
		}
		case CommandList::SendIpTable:
		{
			std::cout << "Run SendIpTable" << std::endl;

			break;
		}
		case CommandList::SendTransaction:
		{
			std::cout << "Run SendTransaction" << std::endl;
			if (DefiningNode_ != LevelNodes::Main)
			{

			}
			break;
		}
		case CommandList::SendTransactionList:
		{
			std::cout << "Run SendTransactionList" << std::endl;

			break;
		}
		case CommandList::SendVector:
		{
			std::cout << "Run SendVector" << std::endl;

			break;
		}
		case CommandList::SendMatrix:
		{
			std::cout << "Run SendMatrix" << std::endl;

			break;
		}
		default:
		{
			std::cout << "Incorrect command" << std::endl;
			break;
		}
	}

}

SessionIO::~SessionIO()
{
	
}

void SessionIO::Begin()
{
	memset(&RecvBuffer, 0, sizeof(RecvBuffer));
	InputServiceSocket_->async_receive_from(
			boost::asio::buffer(&RecvBuffer, sizeof(RecvBuffer)), InputServiceSendEndpoint_,
			boost::bind(&SessionIO::InputServiceHandleReceive, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
	if (OneReg)
	{
		std::cout << "Connect... " << std::endl;
		timer.async_wait(boost::bind(&SessionIO::RegistrationToServer, this));
		io_service_client_.run();
	}
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
			}
			else
			{
				std::cout << "Connect... NO" << std::endl;
				Begin();
				return;
			}
		}

		InRegistrationNode();

		switch (RecvBuffer.command)
		{
			case CommandList::Redirect:
			{
				std::cout << "Run Redirect" << std::endl;
				if (!RunRedirect(bytes_transferred))
				{
					Begin();
				}
				else
				{	
					switch (RecvBuffer.subcommand)
					{
						case SubCommandList::RegistrationLevelNode:
						{
							std::cout << "Run SelectionProcess" << std::endl;
							InRegistrationLevelNode(bytes_transferred);
							break;
						}
						case SubCommandList::GiveHash:
						{
							SolverGiveHash(bytes_transferred);
							break;
						}
						case SubCommandList::GetBlock:
						{
							std::cout << "Run GetBlock" << std::endl;
							if (DefiningNode_ == LevelNodes::Normal)
							{

							}
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
				std::cout << "Run GetHash" << std::endl;
				if (DefiningNode_ == LevelNodes::Write)
				{
					
				}
				break;
			}
			case CommandList::GetMatrix:
			{
				std::cout << "Run GetMatrix" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
					
				}
				break;
			}
			case CommandList::GetTransaction:
			{
				std::cout << "Run GetTransaction" << std::endl;
				if (DefiningNode_ == LevelNodes::Main)
				{
					
				}
				break;
			}
			case CommandList::GetTransactionList:
			{
				std::cout << "Run GetTransactionList" << std::endl;
				if (DefiningNode_ == LevelNodes::Ñonfidant)
				{
					
				}
				break;
			}
			case CommandList::GetVector:
			{
				std::cout << "Run GetVector" << std::endl;
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
		std::cerr << "Error receiving information: " << error.message() << std::endl;
	}
	Begin();
}


void SessionIO::OutputServiceSendCommand(const Packet & pack, unsigned int lenData)
{
	OutputServiceSocket_->async_send_to(boost::asio::buffer(&pack, lenData), OutputServiceSendEndpoint_,
		boost::bind(&SessionIO::OutputServiceHandleSend, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}


void SessionIO::OutputServiceHandleSend(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (!error)
	{

	}
	else
	{
		std::cerr << "Error sending information: " << error.message() << std::endl;
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
				boost::bind(&SessionIO::OutputServiceHandleSend, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
		boost::this_thread::sleep_for(boost::chrono::milliseconds(3000));
		timer.async_wait(boost::bind(&SessionIO::RegistrationToServer, this));
	}
}



bool SessionIO::RunRedirect(std::size_t bytes_transferred)
{
	//std::lock_guard<boost::detail::spinlock> guard(SpinLock_);
	std::string check((char*)RecvBuffer.data, bytes_transferred - SizePacketHeader);

	for (auto & e : BackData_)
	{
		if (e == check)
		{
			return false;
		}
	}

	BackData_.push_back(check);
	memcpy(RecvBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(RecvBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{;
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(RecvBuffer, bytes_transferred);
		}
	}
	return true;
}

void SessionIO::InRegistrationNode()
{

	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	if (RecvBuffer.command == Registration)
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
	MyPublicKey_ = hash.final();
}

void SessionIO::SolverSendHash(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetHash;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, buffer, buf_size);
	udp::resolver::query query_send(udp::v4(), ip_buffer, host_port_);
	OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	OutputServiceSendCommand(SendBuffer, buf_size + SizePacketHeader);
}

void SessionIO::SolverGetHashAll()
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::GiveHash;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, InputServiceRecvEndpoint_.address().to_string().c_str(), InputServiceRecvEndpoint_.address().to_string().length());
	
	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(SendBuffer, InputServiceRecvEndpoint_.address().to_string().length() + SizePacketHeader);
		}
	}
}

void SessionIO::SolverGiveHash(std::size_t bytes_transferred)
{

}

void SessionIO::GenTableRegistrationLevelNode(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::RegistrationLevelNode;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);
	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(SendBuffer, size + SizePacketHeader);
		}
	}
}

void SessionIO::SolverSendBlock(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::Redirect;
	SendBuffer.subcommand = SubCommandList::GetBlock;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < NodesRing_.size(); i++)
	{
		if (!NodesRing_[i].ip.empty())
		{
			udp::resolver::query query_send(udp::v4(), NodesRing_[i].ip, NodesRing_[i].port);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(SendBuffer, size + SizePacketHeader);
		}
	}
}

void SessionIO::SolverSendTransaction(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetTransaction;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	udp::resolver::query query_send(udp::v4(), GeneralNode_.c_str(), host_port_);
	OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
	OutputServiceSendCommand(SendBuffer, size + SizePacketHeader);
}

void SessionIO::SolverSendTransactionList(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetTransactionList;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < ÑonfidantNodes_.size(); i++)
	{
		if (!ÑonfidantNodes_[i].empty() && ÑonfidantNodes_[i] != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), ÑonfidantNodes_[i].c_str(), host_port_);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(SendBuffer, size + SizePacketHeader);
		}
	}
}

void SessionIO::SolverSendVector(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetVector;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < ÑonfidantNodes_.size(); i++)
	{
		if (!ÑonfidantNodes_[i].empty() && ÑonfidantNodes_[i] != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), ÑonfidantNodes_[i].c_str(), host_port_);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(SendBuffer, size + SizePacketHeader);
		}
	}
}

void SessionIO::SolverSendMatrix(const char * data, unsigned size)
{
	/*std::lock_guard<boost::detail::spinlock> guard(SpinLock_);*/
	SendBuffer.command = CommandList::GetMatrix;
	SendBuffer.subcommand = 0;
	SendBuffer.version = version_;
	SendBuffer.header = 0;
	SendBuffer.countHeader = 0;
	memcpy(SendBuffer.hash, MyHash_.c_str(), MyHash_.length());
	memcpy(SendBuffer.publickKey, MyPublicKey_.c_str(), MyPublicKey_.length());
	memcpy(SendBuffer.data, data, size);

	for (unsigned int i = 0; i < ÑonfidantNodes_.size(); i++)
	{
		if (!ÑonfidantNodes_[i].empty() && ÑonfidantNodes_[i] != InputServiceRecvEndpoint_.address().to_string())
		{
			udp::resolver::query query_send(udp::v4(), ÑonfidantNodes_[i].c_str(), host_port_);
			OutputServiceSendEndpoint_ = *OutputServiceResolver_.resolve(query_send);
			OutputServiceSendCommand(SendBuffer, size + SizePacketHeader);
		}
	}
}

void SessionIO::Run()
{
	Begin();
	io_service_server_.run();
}

constexpr std::size_t SessionIO::CalcSum() const
{
	return sizeof(RecvBuffer.command) + sizeof(RecvBuffer.subcommand) + sizeof(RecvBuffer.version) + sizeof(RecvBuffer.header) + sizeof(RecvBuffer.countHeader) +
			sizeof(RecvBuffer.hash) + sizeof(RecvBuffer.publickKey);
}
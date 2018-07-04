/**
@author Larchenko Roman
@email  LarchenkoRP@mail.ru
@date   01/05/2018
*/

#pragma once

#include <cstdlib>
#include <iostream>
#include <vector>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <deque>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/info_parser.hpp>

#include "Structures.hpp"
#include "Packet.hpp"

using boost::asio::ip::udp;
using namespace boost::asio;

const int CURRENT_VERSION = 45;
const size_t BLAKE2_HASH_LENGTH = 32;

const unsigned MAX_PART = 2048;

namespace Credits {
	class ISolver;
	class Node;
}

/**
@class SessionIO
����� ������������ ������ ������������ ������/�������� ���������� �� ��������� UDP.
*/
class SessionIO
{
public:
	/*!
	* \brief ����������� �� ���������.
	*/
	SessionIO();

	~SessionIO();

	/*!
	* \brief ������� ������� �������.
	*/
	void Run();

	// Talking to Node
	void addToRingBuffer(const boost::asio::ip::address&);

	template <typename CallBack, typename... Args>
	void waitOnTimer(const std::chrono::milliseconds& timeout, CallBack cb, Args... args) {
		auto t = new boost::asio::steady_timer(io_service_client_, timeout);
		t->async_wait([t, cb, args...](const boost::system::error_code& ec) {
			cb(args...);
			delete t;
		});
	}

	PacketPtr getEmptyPacket() { return m_pacman.getFreePack(); }

	TaskId addTaskDirect(std::vector<PacketPtr>&& packets, const CommandList cmd, const SubCommandList smd, const size_t lastSize, const ip::address& ip);
	TaskId addTaskBroadcast(std::vector<PacketPtr>&&, const SubCommandList, const size_t lastSize);

	void removeTask(TaskId tId) { m_taskman.remove(tId); }
	void removeAllTasks() { m_taskman.clear(); }

private:
	ip::address MyIp_;
	Hash MyHash_;            /// ��� ������� ����
	PublicKey MyPublicKey_;  /// ��������� ���� ������� ����

	static std::atomic_bool AwaitingRegistration;
	ip::address signalServerAddr;

	// Default values for target ports
	unsigned short nodePort = 9001;
	unsigned short signalServerPort = 6000;

	std::unique_ptr<Credits::Node> node_;

	/*!
	* \brief ����� ������������ ���������� ����������.
	* \return ������ ��������� ���������� ������ ������/�������� ����������
	*/
	boost::asio::io_service io_service_client_;  /// ������ �������
	
	udp::socket * InputServiceSocket_;           /// Input socket
	udp::endpoint InputServiceRecvEndpoint_;	 /// Local input addr
	udp::endpoint InputServiceSendEndpoint_;     /// Remote sender addr
	udp::resolver InputServiceResolver_;         /// �������� �������

	udp::socket * OutputServiceSocket_;          /// Output socket
	udp::endpoint OutputServiceRecvEndpoint_;    /// Local output addr
	udp::endpoint OutputServiceSendEndpoint_;    /// ������� ����� ������ ����������
	udp::endpoint OutputServiceServerEndpoint_;  /// ������� ����� ����������� �������
	udp::resolver OutputServiceResolver_;		 /// �������� �������

	NodesRing<500> m_nodesRing;						/// ��������� ����� �������� �����
	CircularMap<Hash, uint32_t, 50000> m_backData;	/// ��������� ����� �������� ���������� ����������
	PacketCollector<Hash, 1000, MAX_PART> m_packets;
	PacketManager<2048> m_pacman;
	MessageHasher<BLAKE2_HASH_LENGTH> m_hasher;

	TaskManager m_taskman;
	std::thread m_senderThread;

	char* m_combinedData;

	/*!
	* \brief ����� ������������ ���������� ����������.
	*/
	bool Initialization();

	/*!
	* \brief ����� ������ ����������.
	*/
	inline void InputServiceHandleReceive(PacketPtr message, const boost::system::error_code & error, std::size_t bytes_transferred);
	void outputHandleSend(PacketPtr message, const boost::system::error_code& error, std::size_t bytes_transferred);

	/*!
	* \brief Sending info
	*/
	inline void createSendTasks(const std::vector<PacketPtr>&, const CommandList, const SubCommandList, const size_t lastSize);

	inline void outFrmPack(const PacketPtr, const CommandList, const SubCommandList, const Version, const size_t size_data);
	inline void outSendPack(PacketPtr, std::size_t, const udp::endpoint*);
	inline void handleSend(PacketPtr, std::size_t, const udp::endpoint&);

	void senderThreadRoutine();

	/*!
	* \brief ����� ������� ���� ���������.
	*/
	inline bool GenerationHash();
	void InitConnection();

	void ReceiveRegistration();
	void StartReceive();

	/*!
	* \brief ����� ��������� ���������� �����.
	*/
	inline bool RunRedirect(PacketPtr, std::size_t);
	inline uint32_t getBackDataCounter(PacketPtr);

	inline void RegistrationToServer();

	inline void SendSinhroPacket();
	inline void SendGreetings();
};
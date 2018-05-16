/**
@author Larchenko Roman
@email  LarchenkoRP@mail.ru
@date   01/05/2018
*/

#pragma once


#include <iostream>
#include <vector>
#include <functional>
#include <map>


#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>
#include <boost/shared_ptr.hpp>

#include "sha1.hpp"



using boost::asio::ip::udp;


/**
@class SessionIO
Класс траспортного уровня асинхронного приема/передачи информации по протоколу UDP.
*/
class SessionIO
{
public:
	/*!
	* \brief Конструктор по умолчанию.
	*/
	SessionIO();

	/*!
	* \brief Виртуальный деструктор по умолчанию.
	*/
	virtual ~SessionIO();

	/*!
	* \brief Функция запуска клиента.
	*/
	void Run();

private:

	unsigned int DefiningNode_;				/// Определение уровня узла ( клиента )
	const uint16_t version_ = 1;			/// Версия узла
	const char * host_port_ = { "9001" };	/// Порт хоста по умолчанию
	const char * server_port_ = { "6000" }; /// Порт сигнального сервера по умолчанию
	static bool OneReg;						/// Флаг регистрации 

	SHA1 HashBlock_;
	
	/// Структура узла
	struct PacketNode
	{
		std::string hash; /// Хэш
		std::string key;  /// Ключ
		std::string ip;	  /// IP адрес
		std::string port; /// Порт 
	};

	std::string ServerHash_; /// Хэш сервера
	std::string ServerKey_;  /// Ключ сервера
	std::string MyHash_;     /// Хэш данного узла
	std::string MyPublicKey_;/// Публичный ключ данного узла

	std::vector<std::string> СonfidantNodes_; /// Список доверенных узлов
	std::string GeneralNode_;                 /// Главный узел




	/// Перечисление уровней узла
	enum LevelNodes {
		Normal = 0,    /// Обычный узел
		Сonfidant , /// Доверенный узел
		Main ,      /// Главный узел
		Write       /// Пишущий узел
	};

	/// Перечисление команд
	enum CommandList {
		Registration = 1,         /// Регистрация
		UnRegistration ,		 /// Разрегистрация 
		Redirect ,			 /// Перессылка
		GetHash ,              /// Принять хэш
		SendHash ,		     /// Отправить хэш
		SendTransaction ,      /// Отправить транзакцию
		GetTransaction ,       /// Принять транзакцию
		SendTransactionList ,  /// Отправить транзакционный лист
		GetTransactionList ,   /// Принять транзакционный лист
		SendVector ,           /// Отправить вектор
		GetVector ,			 /// Принять вектор
		SendMatrix ,           /// Отправить матрицу
		GetMatrix ,            /// Принять матрицу
		SendBlock ,            /// Отправить блок данных
		GetHashAll ,          /// Запрос хэш(а) со всех узлов
		SendIpTable ,         /// Разослать список доверенных узлов и главного всем узлам
		SinhroPacket ,
		GiveHash2
	};

	/// Перечисление подкоманд
	enum SubCommandList {
		RegistrationLevelNode = 1, /// Принять список доверенных и главного узла
		GiveHash ,              /// Запрос на хэш
		GetBlock ,			  /// Запрос на блок данных
		GetBlocks
	};

	enum { max_length = 64312, hash_length = 40, publicKey_length = 256 };

	/// Структура буфера приема/передачи информации
	struct Packet
	{
		uint8_t command;                        /// Команда
		uint8_t subcommand;						/// Подкоманда
		uint8_t version;						/// Версия
		uint8_t hash[hash_length];              /// Хэш передающего/принимающего узла
		uint8_t publickKey[publicKey_length];   /// Публичный ключ передающего/принимающего узла
		uint8_t HashBlock[hash_length];			/// Хэш блока
		uint16_t header;						/// Номер заголовка
		uint16_t countHeader;					/// Количество заголовков
		uint8_t data[max_length];               /// Данные
	}RecvBuffer, SendBuffer;

	struct Storage
	{
		uint8_t HashBlock[hash_length];			 /// Хэш блока
		uint16_t header;						 /// Номер заголовка
		bool operator==(const Storage & param)
		{
			return !strncmp((const char*)this->HashBlock, (const char*)param.HashBlock, sizeof(HashBlock)) && 
				this->header == param.header;
		}
	};

	/*!
	* \brief Метод иницилизации внутренних переменных.
	* \return Размер служебной информации буфера приема/передачи информации
	*/
	constexpr std::size_t CalcSum() const;
	unsigned int SizePacketHeader;               /// Размер служебной информации буфера приема/передачи информации

	boost::asio::io_service io_service_client_;  /// Сервис клиента
	boost::asio::io_service io_service_server_;  /// Сервис сервера
	
	udp::socket * InputServiceSocket_;           /// Сокет входной информации 
	udp::endpoint InputServiceRecvEndpoint_;	 /// Сетевой адрес приема информации
	udp::endpoint InputServiceSendEndpoint_;     /// Сетевой адрес принятой информации 
	udp::resolver InputServiceResolver_;         /// Решатель клиента

	udp::socket * OutputServiceSocket_;          /// Сокет выходной информации 
	udp::endpoint OutputServiceRecvEndpoint_;    /// Сетевой адрес приема информации
	udp::endpoint OutputServiceSendEndpoint_;    /// Сетевой адрес выдачи информации
	udp::endpoint OutputServiceServerEndpoint_;  /// Сетевой адрес сигнального сервера
	udp::resolver OutputServiceResolver_;		 /// Решатель сервера

	boost::circular_buffer<PacketNode> NodesRing_;   /// Кольцевой буфер хранения узлов
	boost::circular_buffer<Storage> BackData_;	     /// Кольцевой буфер хранения предыдущей информации

	//boost::detail::spinlock SpinLock_;               /// Cпин-блокировка
	boost::property_tree::ptree config;              /// Класс инициализации
	//boost::asio::deadline_timer timer;				 /// Таймер


	std::string tmp_hash1;
	std::string tmp_hash2;
	std::map<unsigned int, std::string> blocks;

	/*!
	* \brief Метод иницилизации внутренних переменных.
	*/
	void Initialization();

	void InitMap();

	/*!
	* \brief Метод приема информации.
	*/
	void InputServiceHandleReceive(const boost::system::error_code & error, std::size_t bytes_transferred);

	void InputServiceHandleSend(const boost::system::error_code & error, std::size_t bytes_transferred);



	void handle_send(boost::shared_ptr<std::string> /*message*/,
		const boost::system::error_code& /*error*/,
		std::size_t /*bytes_transferred*/);

	void SendBlocks(const char * buff, unsigned int size);

	void GetBlocks2(std::size_t bytes_transferred);

	/*!
	* \brief Метод выдачи информации.
	*/
	void OutputServiceHandleSend(const boost::system::error_code& error, std::size_t bytes_transferred);

	/*!
	* \brief Метод выдачи информации.
	*/
	void OutputServiceSendCommand(const Packet & pack, unsigned int lenData);

	/*!
	* \brief Метод выдачи информации.
	*/
	void SolverSendData(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size, unsigned int cmd);

	/*!
	* \brief Метод выдачи хэш.
	*/
	void SolverSendHash(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size);

	/*!
	* \brief Метод запроса хэш всех узлов.
	*/
	void SolverGetHashAll();

	/*!
	* \brief Метод запроса хэш данного узла.
	*/
	void SolverGiveHash(std::size_t bytes_transferred);

	/*!
	* \brief Метод отправки транзакции.
	*/
	void SolverSendTransaction(const char * data, unsigned size);

	/*!
	* \brief Метод отправки транзакции.
	*/
	void SolverSendTransactionList(const char * data, unsigned size);

	/*!
	* \brief Метод отправки вектора.
	*/
	void SolverSendVector(const char * data, unsigned size);

	/*!
	* \brief Метод отправки матрицы.
	*/
	void SolverSendMatrix(const char * data, unsigned size);

	/*!
	* \brief Метод отправки блока данных.
	*/
	void SolverSendBlock(const char * data, unsigned size);

	/*!
	* \brief Метод генерации доверенных и главного узла.
	*/
	void GenTableRegistrationLevelNode( char * data, unsigned size);

	/*!
	* \brief Метод генерации случайного хэш.
	*/
	void GenerationHash();

	/*!
	* \brief Метод запуска всех процессов.
	*/
	void StartReceive();

	/*!
	* \brief Метод пересылки информации узлам.
	*/
	bool RunRedirect(std::size_t bytes_transferred);
	
	/*!
	* \brief Метод разрегистрация на сигнальном сервере.
	*/
	void InRegistrationNode();

	/*!
	* \brief Метод регистрации доверенных и главного узла.
	*/
	void InRegistrationLevelNode(std::size_t bytes_transferred);

	/*!
	* \brief Метод регистрации на сигнальном сервере.
	*/
	void RegistrationToServer();

	void GenHashBlock(const char * buff, unsigned int size);

	void SendSinhroPacket();

	void DefiningNode(unsigned int init);
	
	std::function<void(char * buffer, unsigned int buf_size, char * ip_buffer, unsigned int ip_size, unsigned int cmd)> SolverSendData_;
};


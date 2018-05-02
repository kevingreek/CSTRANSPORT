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

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>

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

	unsigned int DefiningNode_;		/// Определение уровня узла ( клиента )
	const uint16_t version_ = 1;		/// Версия узла
	const char * host_port_ = { "9001" };	/// Порт хоста по умолчанию
	const char * server_port_ = { "6000" }; /// Порт сигнального сервера по умолчанию
	static bool OneReg;			/// Флаг регистрации 
	
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
		Normal = 0x00,    /// Обычный узел
		Сonfidant = 0x01, /// Доверенный узел
		Main = 0x02,      /// Главный узел
		Write = 0x03      /// Пишущий узел
	};

	/// Перечисление команд
	enum CommandList {
		Registration = 0x01,         /// Регистрация
		UnRegistration = 0x02,	     /// Разрегистрация 
		Redirect = 0x03,	     /// Перессылка
		GetHash = 0x04,              /// Принять хэш
		SendHash = 0x05,             /// Отправить хэш
		SendTransaction = 0x06,      /// Отправить транзакцию
		GetTransaction = 0x07,       /// Принять транзакцию
		SendTransactionList = 0x08,  /// Отправить транзакционный лист
		GetTransactionList = 0x09,   /// Принять транзакционный лист
		SendVector = 0x10,           /// Отправить вектор
		GetVector = 0x11,	     /// Принять вектор
		SendMatrix = 0x12,           /// Отправить матрицу
		GetMatrix = 0x13,            /// Принять матрицу
		SendBlock = 0x14,            /// Отправить блок данных
		GetHashAll = 0x015,          /// Запрос хэш(а) со всех узлов
		SendIpTable = 0x016          /// Разослать список доверенных узлов и главного всем узлам
	};

	/// Перечисление подкоманд
	enum SubCommandList {
		RegistrationLevelNode = 0x01, /// Принять список доверенных и главного узла
		GiveHash = 0x02,              /// Запрос на хэш
		GetBlock = 0x03,	      /// Запрос на блок данных
	};

	enum { max_length = 65447, hash_length = 40, publicKey_length = 40 };

	/// Структура буфера приема/передачи информации
	struct Packet
	{
		uint8_t command;                        /// Команда
		uint8_t subcommand;			/// Подкоманда
		uint8_t version;			/// Версия
		uint16_t header;			/// Номер заголовка
		uint16_t countHeader;			/// Количество заголовков
		uint8_t hash[hash_length];              /// Хэш передающего/принимающего узла
		uint8_t publickKey[publicKey_length];   /// Публичный ключ передающего/принимающего узла
		uint8_t data[max_length];               /// Данные
	}RecvBuffer, SendBuffer;

	/*!
	* \brief Метод иницилизации внутренних переменных.
	* \return Размер служебной информации буфера приема/передачи информации
	*/
	constexpr std::size_t CalcSum() const;
	unsigned int SizePacketHeader;               /// Размер служебной информации буфера приема/передачи информации

	boost::asio::io_service io_service_client_;  /// Сервис клиента
	boost::asio::io_service io_service_server_;  /// Сервис сервера
	
	udp::socket * InputServiceSocket_;           /// Сокет входной информации 
	udp::endpoint InputServiceRecvEndpoint_;     /// Сетевой адрес приема информации
	udp::endpoint InputServiceSendEndpoint_;     /// Сетевой адрес принятой информации 
	udp::resolver InputServiceResolver_;         /// Решатель клиента

	udp::socket * OutputServiceSocket_;          /// Сокет выходной информации 
	udp::endpoint OutputServiceRecvEndpoint_;    /// Сетевой адрес приема информации
	udp::endpoint OutputServiceSendEndpoint_;    /// Сетевой адрес выдачи информации
	udp::endpoint OutputServiceServerEndpoint_;  /// Сетевой адрес сигнального сервера
	udp::resolver OutputServiceResolver_;		 /// Решатель сервера

	boost::circular_buffer<PacketNode> NodesRing_;   /// Кольцевой буфер хранения узлов
	boost::circular_buffer<std::string> BackData_;	 /// Кольцевой буфер хранения предыдущей информации

	boost::detail::spinlock SpinLock_;               /// Cпин-блокировка
	boost::property_tree::ptree config;              /// Класс инициализации
	boost::asio::deadline_timer timer;				 /// Таймер


	
	/*!
	* \brief Метод иницилизации внутренних переменных.
	*/
	void Initialization();

	/*!
	* \brief Метод приема информации.
	*/
	void InputServiceHandleReceive(const boost::system::error_code& error, std::size_t bytes_transferred);

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
	void GenTableRegistrationLevelNode(const char * data, unsigned size);

	/*!
	* \brief Метод генерации случайного хэш.
	*/
	void GenerationHash();

	/*!
	* \brief Метод запуска всех процессов.
	*/
	void Begin();

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

	void DefiningNode(unsigned int init);
	
};

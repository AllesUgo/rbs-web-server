// http-server.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。

#pragma once
#include <string>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <regex>
#include <fstream>
#include <thread>
#include <map>
#include "rbslib/Buffer.h"
#include "rbslib/Storage.h"
#include "rbslib/FileIO.h"
#include "rbslib/Network.h"
#include "rbslib/URLEncoder.h"
#include "liblog/logger.h"
#include "json/CJsonObject.h"
#include "ConstStrings.h"
#ifdef LINUX
#include <signal.h>
#endif // LINUX


int main(int argc, char** argv);
/*
* 检查配置有效性，如文件夹是否存在
*/
bool CheckingConfig();
neb::CJsonObject LoadMimeJson();


class Configuration
{
public:
	inline static std::string addr;
	inline static int port = -1;
	inline static std::filesystem::path doc_root_path;
	inline static std::string server_name;
	inline static std::string server_version;
	inline static std::string cgi_path;
	inline static std::string cgi_mapping_url;
	inline static std::filesystem::path mime_path;
	inline static std::filesystem::path log_path;
	inline static std::filesystem::path default_page;
	inline static std::map<std::string, std::string> cgi_env;//cgi环境变量
	static bool LoadConfigurationFile(std::filesystem::path path);
	static bool SaveConfigurationFile(std::filesystem::path path);
	static void GenerateDefaultConfiguration(void);
};

class CGIExecuter
{
public:
	static int ExecuteCGI(std::string cgi_path,const std::string& query_string, const RbsLib::Network::TCP::TCPConnection& connection, const RbsLib::Network::HTTP::RequestHeader& header, const RbsLib::Buffer& buffer);
};

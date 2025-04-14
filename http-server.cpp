// http-server.cpp: 定义应用程序的入口点。
//

#include "http-server.h"

bool Configuration::LoadConfigurationFile(std::filesystem::path path)
{
	if (!std::filesystem::exists(path))
	{
		std::cout << "配置文件不存在" << std::endl;
		return false;
	}
	RbsLib::Storage::FileIO::File file(path.string(), RbsLib::Storage::FileIO::OpenMode::Read);
	auto buffer = file.Read(RbsLib::Storage::StorageFile(path).GetFileSize());
	neb::CJsonObject config_json;
	std::string temp_string;
	if (!config_json.Parse(buffer.ToString()))
	{
		std::cout << "配置文件解析失败" << std::endl;
		return false;
	}
	if (!config_json.Get("addr", Configuration::addr))
	{
		std::cout << "配置文件缺少addr字段" << std::endl;
	}
	if (!config_json.Get("port", Configuration::port))
	{
		std::cout << "配置文件缺少port字段" << std::endl;
	}
	if (!config_json.Get("doc_root_path", temp_string))
	{
		std::cout << "配置文件缺少doc_root_path字段" << std::endl;
	}
	else
	{
		Configuration::doc_root_path = temp_string;
	}
	if (!config_json.Get("server_name", Configuration::server_name))
	{
		std::cout << "配置文件缺少server_name字段" << std::endl;
	}
	if (!config_json.Get("server_version", Configuration::server_version))
	{
		std::cout << "配置文件缺少server_version字段" << std::endl;
	}
	if (!config_json.Get("cgi_path", temp_string))
	{
		std::cout << "配置文件缺少cgi_path字段" << std::endl;
	}
	else
	{
		Configuration::cgi_path = temp_string;
	}
	if (!config_json.Get("cgi_mapping_url", Configuration::cgi_mapping_url))
	{
		std::cout << "配置文件缺少cgi_mapping_url字段" << std::endl;
	}
	if (!config_json.Get("mime_path", temp_string))
	{
		std::cout << "配置文件缺少mime_path字段" << std::endl;
	}
	else
	{
		Configuration::mime_path = temp_string;
	}
	if (!config_json.Get("log_path", temp_string))
	{
		std::cout << "配置文件缺少log_path字段" << std::endl;
	}
	else
	{
		Configuration::log_path = temp_string;
	}
	if (!config_json.Get("default_page", temp_string))
	{
		std::cout << "配置文件缺少default_page字段" << std::endl;
	}
	else
	{
		Configuration::default_page = temp_string;
	}
	return true;
}

bool Configuration::SaveConfigurationFile(std::filesystem::path path)
{
   try
   {
       neb::CJsonObject config_json;
       config_json.Add("addr", Configuration::addr);
       config_json.Add("port", Configuration::port);
       config_json.Add("doc_root_path", Configuration::doc_root_path.string());
       config_json.Add("server_name", Configuration::server_name);
       config_json.Add("server_version", Configuration::server_version);
       config_json.Add("cgi_path", Configuration::cgi_path);
       config_json.Add("cgi_mapping_url", Configuration::cgi_mapping_url);
       config_json.Add("mime_path", Configuration::mime_path.string());
       config_json.Add("log_path", Configuration::log_path.string());
       config_json.Add("default_page", Configuration::default_page.string());

       std::ofstream config_file(path);
       if (!config_file.is_open())
       {
           std::cout << "无法打开配置文件进行写入" << std::endl;
           return false;
       }

       config_file << config_json.ToFormattedString();
       config_file.close();
       return true;
   }
   catch (const std::exception& e)
   {
       std::cout << "保存配置文件时发生错误: " << e.what() << std::endl;
       return false;
   }
}

void Configuration::GenerateDefaultConfiguration(void)
{
	Configuration::addr = "0.0.0.0";
	Configuration::port = 80;
	Configuration::server_name = "RBS Web Server";
	Configuration::server_version = "alpha v0.1";
	Configuration::doc_root_path = "./hdocs/";
	Configuration::cgi_path = "./cgi/";
	Configuration::log_path = "./log/";
	Configuration::mime_path = "./mime.json";
	Configuration::default_page = "index.html";
	Configuration::cgi_mapping_url = "cgi-bin";
}

int main(int argc, char** argv)
{
	//Linux下忽略SIGPIPE信号
#ifdef LINUX
	signal(SIGPIPE, SIG_IGN);
#endif

	//加载当前目录下的config.json作为配置文件
	std::filesystem::path config_path = std::filesystem::current_path() / "config.json";
	if (argc > 1)
	{
		config_path = argv[1];
	}
	//加载配置文件
	if (!Configuration::LoadConfigurationFile(config_path))
	{
		std::cout << "加载配置文件失败，是否生成默认配置文件? (y/n)" << std::endl;
		std::string answer;
		std::cin >> answer;
		if (answer == "y" || answer == "Y")
		{
			Configuration::GenerateDefaultConfiguration();
			if (!Configuration::SaveConfigurationFile(config_path))
			{
				std::cout << "保存默认配置文件失败" << std::endl;
				return 1;
			}
			std::cout << "默认配置文件已生成，请修改后重新运行" << std::endl;
			return 0;
		}
		else
		{
			return 1;
		}
	}

	//生成MIME类型配置文件
	if (!std::filesystem::exists(Configuration::mime_path))
	{
		std::ofstream mime_file(Configuration::mime_path.string());
		mime_file << DEFAULT_MIME;
		mime_file.close();
	}
	if (!CheckingConfig())
	{
		std::cout << "请修正配置文件后再次尝试" << std::endl;
		return 1;
	}
	//初始化日志系统
	if (!Logger::Init(Configuration::log_path.string(), 0, 0))
	{
		std::cout << "日志系统初始化失败" << std::endl;
		return 2;
	}
	try
	{
		auto mime_json = LoadMimeJson();
		//创建HTTP服务器对象
		Logger::LogInfo("已设置置服务器名称为%s", Configuration::server_name.c_str());
		Logger::LogInfo("已设置置服务器版本为%s", Configuration::server_version.c_str());
		Logger::LogInfo("已设置置文档根目录为%s", Configuration::doc_root_path.string().c_str());
		Logger::LogInfo("已设置置CGI目录为%s", Configuration::cgi_path.c_str());
		Logger::LogInfo("已设置置CGI映射URL为%s", Configuration::cgi_mapping_url.c_str());
		Logger::LogInfo("已设置置MIME类型配置文件为%s", Configuration::mime_path.string().c_str());
		Logger::LogInfo("已设置置日志目录为%s", Configuration::log_path.string().c_str());
		Logger::LogInfo("已设置置默认页面为%s", Configuration::default_page.string().c_str());
		Logger::LogInfo("使用地址%s:%d 启动服务器", Configuration::addr.c_str(), Configuration::port);
		RbsLib::Network::HTTP::HTTPServer http_server(Configuration::addr, Configuration::port);
		http_server.SetGetHandle([&mime_json](const RbsLib::Network::TCP::TCPConnection& connection, RbsLib::Network::HTTP::RequestHeader& header) {
			try
			{
				RbsLib::Network::HTTP::ResponseHeader response;
				response.headers.AddHeader("Server", Configuration::server_name);
				//如果URL是空，则重定向到默认页面
				if (header.path == "/")
				{
					response.status = 302;
					response.status_descraption = "Found";
					response.headers.AddHeader("Location", Configuration::default_page.string());
					connection.Send(response.ToBuffer());
					return 0;
				}
				//URL解码
				auto url = RbsLib::Encoding::URLEncoder::Decode(header.path);
				//去除URL的前导斜杠
				if (!url.empty() and url[0] == '/') url = url.substr(1);
				//使用正则表达式匹配路径是否属于CGI
				std::regex cgi_regex("^" + Configuration::cgi_mapping_url + "/.*");
				//用正则表达式获取CGI路径，注意路径可能结束于?、#、/或行尾
				std::smatch cgi_match;
				cgi_regex = std::regex("^" + Configuration::cgi_mapping_url + "/([^?/#]*)");
				//获取QueryString部分
				std::string query_string;
				if (header.path.find('?') != std::string::npos)
				{
					query_string = header.path.substr(header.path.find('?') + 1);
					url = url.substr(0, url.find('?'));
				}
				if (std::regex_search(url, cgi_match, cgi_regex))
				{
					//CGI处理
					std::string cgi_path = Configuration::cgi_path + cgi_match[1].str();
					//检查CGI路径是否存在
					if (!std::filesystem::exists(cgi_path))
					{
						//CGI路径不存在,返回404
						response.status = 404;
						response.status_descraption = "Not Found";
						response.headers.AddHeader("Content-Type", "text/html");
						std::string html = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";
						response.headers.AddHeader("Content-Length", std::to_string(html.size()));
						connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
					}
					else if (RbsLib::Storage::StorageFile(cgi_path).GetFileType() != RbsLib::Storage::FileType::Regular)
					{
						//文件类型错误，返回403
						response.status = 403;
						response.status_descraption = "Forbidden";
						response.headers.AddHeader("Content-Type", "text/html");
						std::string html = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>";
						response.headers.AddHeader("Content-Length", std::to_string(html.size()));
						connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
					}
					else
					{
						//执行CGI
						CGIExecuter::ExecuteCGI(cgi_path, query_string, connection, header, RbsLib::Buffer());
					}
				}
				else
				{
					//普通文件处理
					std::filesystem::path file_path = Configuration::doc_root_path / url;
					if (std::filesystem::exists(file_path))
					{
						if (RbsLib::Storage::StorageFile(file_path).GetFileType() == RbsLib::Storage::FileType::Regular)
						{
							//获取文件类型
							std::string mime_type = mime_json(file_path.extension().string());
							if (mime_type.empty())
								mime_type = "application/octet-stream";
							response.headers.AddHeader("Content-Type", mime_type);
							std::size_t final_start, final_size;//用于存储最终需要发送的文件大小和起始位置
							//检查是否要获取文件的某一部分，依据请求构造头部和文件范围
							if (header.headers.ExistHeader("Range"))
							{
								//获取文件的某一部分
								std::string range = header.headers.GetHeader("Range");
								std::regex range_regex("bytes=(\\d+)-(\\d+)?");
								std::smatch range_match;
								if (std::regex_search(range, range_match, range_regex))
								{
									int64_t start = -1, end = -1;
									//获取范围
									try
									{
										start = std::stoll(range_match[1].str());
										
									}
									catch (...) {}//允许范围一边没有数字
									try
									{
										end = std::stoll(range_match[2].str());
									}
									catch (...) {}
									if (start == -1 and end == -1)
									{
										response.status = 416;
										response.status_descraption = "Requested Range Not Satisfiable";
										response.headers.AddHeader("Content-Range", "bytes */" + std::to_string(RbsLib::Storage::StorageFile(file_path).GetFileSize()));
										connection.Send(response.ToBuffer());
										return 0;
									}
									if (start == -1) start = 0;
									if (end == -1) end = RbsLib::Storage::StorageFile(file_path).GetFileSize() - 1;
									if (end == 0) end = RbsLib::Storage::StorageFile(file_path).GetFileSize() - 1;
									if (start > end)
									{
										response.status = 416;
										response.status_descraption = "Requested Range Not Satisfiable";
										response.headers.AddHeader("Content-Range", "bytes */" + std::to_string(RbsLib::Storage::StorageFile(file_path).GetFileSize()));
										connection.Send(response.ToBuffer());
										return 0;
									}
									//检查文件大小是否超过范围
									if (end >= RbsLib::Storage::StorageFile(file_path).GetFileSize())
									{
										end = RbsLib::Storage::StorageFile(file_path).GetFileSize() - 1;
									}
									response.status = 206;
									response.status_descraption = "Partial Content";
									response.headers.AddHeader("Content-Range", "bytes " + std::to_string(start) + "-" + std::to_string(end) + "/" + std::to_string(RbsLib::Storage::StorageFile(file_path).GetFileSize()));
									final_start = start;
									final_size = end - start + 1;
								}
								else
								{
									response.status = 416;
									response.status_descraption = "Requested Range Not Satisfiable";
									response.headers.AddHeader("Content-Range", "bytes */" + std::to_string(RbsLib::Storage::StorageFile(file_path).GetFileSize()));
									connection.Send(response.ToBuffer());
									return 0;
								}
							}
							else
							{
								//没有分段请求，直接发送整个文件
								response.status = 200;
								response.status_descraption = "OK";
								final_size = RbsLib::Storage::StorageFile(file_path).GetFileSize();
								final_start = 0;
							}
							//发送头部

							response.headers.AddHeader("Accept-Ranges", "bytes");
							response.headers.AddHeader("Content-Length", std::to_string(final_size));
							connection.Send(response.ToBuffer());
							//读取文件，每次最多读取64K
							RbsLib::Storage::FileIO::File file(file_path.string(), RbsLib::Storage::FileIO::OpenMode::Read | RbsLib::Storage::FileIO::OpenMode::Bin, RbsLib::Storage::FileIO::SeekBase::begin, final_start);
							RbsLib::Streams::FileInputStream file_stream(file);
							const std::size_t buffer_size = 1024 * 1024;
							RbsLib::Buffer buffer(buffer_size);
							while (final_size)
							{
								file_stream.Read(buffer, buffer.GetSize() > final_size ? final_size : buffer_size);
								connection.Send(buffer);
								final_size -= buffer.GetLength();
							}
						}
						else
						{
							//文件类型错误，返回403
							response.status = 403;
							response.status_descraption = "Forbidden";
							response.headers.AddHeader("Content-Type", "text/html");
							std::string html = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>";
							response.headers.AddHeader("Content-Length", std::to_string(html.size()));
							auto b = response.ToBuffer();
							b.AppendToEnd(RbsLib::Buffer(html));
							connection.Send(b);
						}
					}
					else
					{
						//文件不存在，返回404
						response.status = 404;
						response.status_descraption = "Not Found";
						response.headers.AddHeader("Content-Type", "text/html");
						std::string html = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";
						response.headers.AddHeader("Content-Length", std::to_string(html.size()));
						connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
					}
				}
				return 0;
			}
			catch (const std::exception& ex)
			{
				//发生异常，返回500
				RbsLib::Network::HTTP::ResponseHeader response;
				response.status = 500;
				response.status_descraption = "Internal Server Error";
				response.headers.AddHeader("Content-Type", "text/html");
				response.headers.AddHeader("Connection", "close");
				std::string html = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1></body></html>";
				response.headers.AddHeader("Content-Length", std::to_string(html.size()));
				connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
				Logger::LogError("发生错误: %s", ex.what());
				return -1;
			}

			});

			http_server.SetPostHandle([&mime_json](const RbsLib::Network::TCP::TCPConnection& connection, RbsLib::Network::HTTP::RequestHeader& header, RbsLib::Buffer& post_content) {
				try
				{
					RbsLib::Network::HTTP::ResponseHeader response;
					response.headers.AddHeader("Server", Configuration::server_name);
					//URL解码
					auto url = RbsLib::Encoding::URLEncoder::Decode(header.path);
					//去除URL的前导斜杠
					if (!url.empty() and url[0] == '/') url = url.substr(1);
					//使用正则表达式匹配路径是否属于CGI
					std::regex cgi_regex("^" + Configuration::cgi_mapping_url + "/.*");
					//用正则表达式获取CGI路径，注意路径可能结束于?、#、/或行尾
					std::smatch cgi_match;
					cgi_regex = std::regex("^" + Configuration::cgi_mapping_url + "/([^?/#]*)");
					//获取QueryString部分
					std::string query_string;
					if (header.path.find('?') != std::string::npos)
					{
						query_string = header.path.substr(header.path.find('?') + 1);
						url = url.substr(0, url.find('?'));
					}
					if (std::regex_search(url, cgi_match, cgi_regex))
					{
						//CGI处理
						std::string cgi_path = Configuration::cgi_path + cgi_match[1].str();
						//检查CGI路径是否存在
						if (!std::filesystem::exists(cgi_path))
						{
							//CGI路径不存在,返回404
							response.status = 404;
							response.status_descraption = "Not Found";
							response.headers.AddHeader("Content-Type", "text/html");
							std::string html = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";
							response.headers.AddHeader("Content-Length", std::to_string(html.size()));
							connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));

						}
						else if (RbsLib::Storage::StorageFile(cgi_path).GetFileType() != RbsLib::Storage::FileType::Regular)
						{
							//文件类型错误，返回403
							response.status = 403;
							response.status_descraption = "Forbidden";
							response.headers.AddHeader("Content-Type", "text/html");
							std::string html = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>";
							response.headers.AddHeader("Content-Length", std::to_string(html.size()));
							connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
						}
						else
						{
							//执行CGI
							CGIExecuter::ExecuteCGI(cgi_path, query_string, connection, header, post_content);
						}
					}
					else
					{
						//尝试用POST获取文件，返回错误
						response.status = 405;
						response.status_descraption = "Method Not Allowed";
						response.headers.AddHeader("Content-Type", "text/html");
						std::string html = "<html><head><title>405 Method Not Allowed</title></head><body><h1>405 Method Not Allowed</h1></body></html>";
						response.headers.AddHeader("Content-Length", std::to_string(html.size()));
						connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
					}
					return 0;
				}
				catch (const std::exception& ex)
				{
					//发生异常，返回500
					RbsLib::Network::HTTP::ResponseHeader response;
					response.status = 500;
					response.status_descraption = "Internal Server Error";
					response.headers.AddHeader("Content-Type", "text/html");
					response.headers.AddHeader("Connection", "close");
					std::string html = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1></body></html>";
					response.headers.AddHeader("Content-Length", std::to_string(html.size()));
					connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
					Logger::LogError("发生错误: %s", ex.what());
					return -1;
				}
				});
			
			http_server.LoopWait(true,20);
	}
	catch (const std::exception& e)
	{
		Logger::LogError("发生错误: %s", e.what());
		return 3;
	}
	return 0;
}

bool CheckingConfig()
{
	std::string error_list;
	if (Configuration::port < 0 or Configuration::port > 65535)
		error_list += "端口应在0-65535之间\n";
	if (!std::filesystem::exists(Configuration::doc_root_path))
		error_list += "HTML文档目录不存在\n";
	else if (RbsLib::Storage::StorageFile(Configuration::doc_root_path).GetFileType() != RbsLib::Storage::FileType::Dir)
		error_list += "HTML文档目录不是一个目录\n";
	if (!std::filesystem::exists(Configuration::mime_path))
		error_list += "MIME类型配置文件不存在\n";
	else if (RbsLib::Storage::StorageFile(Configuration::mime_path).GetFileType() != RbsLib::Storage::FileType::Regular)
		error_list += "MIME类型配置文件不是一个文件\n";
	if (!std::filesystem::exists(Configuration::cgi_path))
		error_list += "CGI目录不存在\n";
	else if (RbsLib::Storage::StorageFile(Configuration::cgi_path).GetFileType() != RbsLib::Storage::FileType::Dir)
		error_list += "CGI目录不是一个目录\n";
	if (Configuration::cgi_mapping_url.empty())
		error_list += "CGI映射URL不能为空\n";
	if (std::filesystem::exists(Configuration::log_path))
		if (RbsLib::Storage::StorageFile(Configuration::log_path).GetFileType() != RbsLib::Storage::FileType::Dir)
			error_list += "日志目录已存在且不是目录\n";
	if (!error_list.empty())
	{
		std::cout << "配置文件存在以下错误:\n" << error_list;
		return false;
	}
	return true;
}

neb::CJsonObject LoadMimeJson()
{
	neb::CJsonObject mime_json;
	auto buffer = RbsLib::Storage::FileIO::File(Configuration::mime_path.string()).Read(RbsLib::Storage::StorageFile(Configuration::mime_path).GetFileSize());
	if (!mime_json.Parse(buffer.ToString()))
	{
		throw std::runtime_error("MIME类型配置文件解析失败");
	}
	return mime_json;
}
#ifdef WIN32
#include <windows.h>
#include <namedpipeapi.h>
#include <io.h>
#include <fcntl.h>
void CGIExecuter::ExecuteCGI(std::string cgi_path,const std::string&query_string, const RbsLib::Network::TCP::TCPConnection& connection, const RbsLib::Network::HTTP::RequestHeader& header, const RbsLib::Buffer& buffer)
{
	//从cgi_path中查找QUERY_STRING部分
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hReadPipe = NULL, hWritePipe = NULL;
	BOOL bSuccess = FALSE;

	// 设置安全属性，使句柄可继承
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;  // 关键：允许继承
	sa.lpSecurityDescriptor = NULL;

	//设置子进程的环境变量在继承父进程的基础上增加HTTP请求头
	std::size_t env_size = 1;//=1 for last '\0'
	RbsLib::Network::HTTP::RequestHeader header_copy = header;
	//添加CGI环境变量
	std::string method;
	switch (header_copy.request_method)
	{
	case RbsLib::Network::HTTP::Method::GET:
		method = "GET";
		break;
	case RbsLib::Network::HTTP::Method::POST:
		method = "POST";
		break;
	default:
		method = "GET";
		break;
	}
	header_copy.headers.AddHeader("REQUEST_METHOD", method);
	if (!cgi_path.empty()) header_copy.headers.AddHeader("SCRIPT_NAME", cgi_path);
	if (!query_string.empty())header_copy.headers.AddHeader("QUERY_STRING", query_string);
	header_copy.headers.AddHeader("SERVER_NAME", Configuration::server_name);
	header_copy.headers.AddHeader("SERVER_PORT", std::to_string(Configuration::port));
	header_copy.headers.AddHeader("SERVER_PROTOCOL", "HTTP/1.1");
	header_copy.headers.AddHeader("SERVER_SOFTWARE", Configuration::server_version);
	header_copy.headers.AddHeader("REMOTE_ADDR", connection.GetAddress());

	for (const auto& header : header_copy.headers.GetHeaderMap())
	{
		env_size += header.first.size() + header.second.size() + 2; // +2 for '=' and '\0'
	}
	RbsLib::Buffer env_buf(env_size);
	for (const auto& header : header_copy.headers.GetHeaderMap())
	{
		env_buf.AppendToEnd(RbsLib::Buffer(header.first + '=' + header.second, true));
	}
	env_buf.AppendToEnd(RbsLib::Buffer(std::string(), true));

	//--------------------------------------------------------------------------------
	// 在此之后产生异常，可能导致资源无法正确释放，将可能产生异常的操作移至之前或使用try-catch捕获
	// 创建匿名管道 parent->child
	bSuccess = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if (!bSuccess) {
		throw std::runtime_error("CreatePipe failed");
	}
	// child -> parent
	HANDLE hReadPipe2 = NULL, hWritePipe2 = NULL;
	// 创建匿名管道 child->parent
	bSuccess = CreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0);
	if (!bSuccess) {
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		throw std::runtime_error("CreatePipe failed");
	}
	//使用DuplicateHandle将子进程不需要的两个句柄设置为不可继承
	HANDLE hTemp = NULL;
	bSuccess = DuplicateHandle(GetCurrentProcess(), hWritePipe, GetCurrentProcess(), &hWritePipe, 0, FALSE, DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS);
	if (!bSuccess)
	{
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe2);
		CloseHandle(hWritePipe2);
		throw std::runtime_error("DuplicateHandle failed");
	}
	bSuccess = DuplicateHandle(GetCurrentProcess(), hReadPipe2, GetCurrentProcess(), &hReadPipe2, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
	if (!bSuccess)
	{
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe2);
		CloseHandle(hWritePipe2);
		throw std::runtime_error("DuplicateHandle failed");
	}

	// 子进程配置
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	si.hStdInput = hReadPipe;  // 将管道的读取端作为子进程的标准输入
	si.hStdOutput = hWritePipe2;  // 将管道的写入端作为子进程的标准输出
	si.dwFlags = STARTF_USESTDHANDLES;

	
	// 创建子进程（例如启动一个控制台程序）
	char cmd[256];
	strncpy(cmd, cgi_path.c_str(), sizeof(cmd) - 1);
	cmd[sizeof(cmd) - 1] = 0;
	bSuccess = CreateProcessA(
		cmd, cmd, NULL, NULL,
		TRUE,  // 继承父进程句柄
		0, (void*)env_buf.Data(), NULL, &si, &pi);
	//关闭父进程的无用端口
	CloseHandle(hReadPipe);
	CloseHandle(hWritePipe2);
	if (!bSuccess)
	{
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe2);
		std::cout << GetLastError() << std::endl;
		throw std::runtime_error("CreateProcess failed");
	}
	//创建一个线程来读取子进程的输出，并转发到浏览器
	std::thread read_thread([hReadPipe2, &connection,&pi]() {
		//子线程不管理资源，因此无需考虑异常导致资源无法释放的问题
		RbsLib::Buffer buffer(64 * 1024);
		//读取HTTP头部
		//解析HTTP头部且拒绝HTTP的协议行，并获取Status行
			//在读取头部时，如果遇到连续的两个\r则合并为一个\r，这可能是因为CGI程序输出的\n被转换为\r\n
		//先读取整个HTTP头部，可能会读取部分HTTP响应体，但要保证能读取到完整的头部并放在buffer中
		while (buffer.GetLength()<buffer.GetSize())
		{
			DWORD bytes_read;
			BOOL bSuccess = ReadFile(hReadPipe2, (char*)buffer.Data()+buffer.GetLength(), (DWORD)buffer.GetSize()-(DWORD)buffer.GetLength(), &bytes_read, NULL);
			if (!bSuccess || bytes_read == 0)
			{
				int a = GetLastError();
				break;
			}
			buffer.SetLength(buffer.GetLength() + bytes_read);
			//退出循环时如果还没有读取到\r\n\r\n，则表示头部大小过大。
		}
		//解析头部
		int status = 0;//状态机，0表示位于key状态，1表示位于value状态，2表示位于行末\r状态，3表示位于行末\n状态,4位于key-value分隔符:状态，5表示位于额外的\r状态,6进入头部结尾状态,7表示位于头部结尾额外的\r状态，8表示完成状态
		std::string key;
		std::string value;
		bool error = false;
		RbsLib::Network::HTTP::ResponseHeader response;
		int content_start_pos;
		bool end = false;
		for (int i = 0; i < buffer.GetLength(); ++i)
		{
			if (error || end)
			{
				content_start_pos = i;
				break;
			}
			switch (status)
			{
			case 0:
				if (buffer[i] == '\r')
				{
					status = 6;
				}
				if (buffer[i] != ':')
					key.append(1, buffer[i]);
				else
				{
					if (key.empty())
					{
						error = true;
						break;
					}
					status = 4;
				}
				break;
			case 4:
				if (buffer[i] != ' ')
					error = true;
				else
					status = 1;
				break;
			case 1:
				if (buffer[i] != '\r')
					value.append(1, buffer[i]);
				else
				{
					if (value.empty())
					{
						error = true;
						break;
					}
					response.headers.AddHeader(key, value);
					key.clear();
					value.clear();
					status = 2;
				}
				break;
			case 2:
				if (buffer[i] == '\r')
				{
					//可能是CGI程序输出的\n被转换为\r\n
					status = 5;
				}
				else if (buffer[i] == '\n')
				{
					status = 0;
				}
				else
				{
					error = true;
					break;
				}
				break;
			case 5:
				if (buffer[i] == '\n')
				{
					status = 0;
				}
				else
				{
					error = true;
					break;
				}
				break;
			case 6:
				if (buffer[i] == '\n')
				{
					//头部读取结束
					end = true;
					status = 8;
				}
				else if (buffer[i] == '\r')
				{
					//可能是CGI程序输出的\n被转换为\r\n
					status = 7;
				}
				else
				{
					error = true;
				}
				break;
			case 7:
				if (buffer[i] == '\n')
				{
					//头部读取结束
					end = true;
					status = 8;
				}
				else
				{
					error = true;
				}
				break;
			}
		}
		//检查是否读取到完整的头部或是否存在错误
		if (error || status != 8)
		{
			error = true;//后续如果检查到error为true，则不向浏览器发送数据，但为了防止卡死子进程，继续读取管道数据
		}
		//检查是否存在Status行
		if (response.headers.ExistHeader("Status"))
		{
			//解析Status行
			std::string status_line = response.headers.GetHeader("Status");
			std::stringstream ss(status_line);
			std::string status_code;
			std::string status_description;
			std::getline(ss, status_code, ' ');
			std::getline(ss, status_description);
			if (status_code.empty())
			{
				error = true;
			}
			else
			{
				response.status = std::stoi(status_code);
				response.status_descraption = status_description;
			}
		}
		else
		{
			response.status = 200;
			response.status_descraption = "OK";
		}
		//发送buffer中剩余的数据
		if (error == 0)
		{
			connection.Send(response.ToBuffer());
			if (buffer.GetLength() > content_start_pos)
			{
				connection.Send((const char*)buffer.Data() + content_start_pos, buffer.GetLength() - content_start_pos);
			}
		}
		//继续读取管道数据并发送到浏览器
		while (true)
		{
			DWORD bytes_read;
			BOOL bSuccess = ReadFile(hReadPipe2, (char*)buffer.Data(), (DWORD)buffer.GetSize(), &bytes_read, NULL);
			if (!bSuccess || bytes_read == 0)
			{
				break;
			}
			if (error == 0) connection.Send(buffer, bytes_read);
		}
		if (error)
		{
			//发送错误信息
			RbsLib::Network::HTTP::ResponseHeader response;
			response.status = 500;
			response.status_descraption = "Internal Server Error";
			response.headers.AddHeader("Content-Type", "text/html");
			response.headers.AddHeader("Connection", "close");
			std::string html = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1></body></html>";
			response.headers.AddHeader("Content-Length", std::to_string(html.size()));
			connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
			//关闭子进程
			TerminateProcess(pi.hProcess, 1);
			Logger::LogError("CGI程序返回了错误的响应");
		}
		});

	// 父进程写入数据到管道（子进程通过stdin读取）
	std::size_t need_write = buffer.GetLength();
	while (need_write)
	{
		std::size_t write_size = buffer.GetLength() > need_write ? need_write : buffer.GetLength();
		DWORD bytes_written;
		bSuccess = WriteFile(hWritePipe, buffer.Data(), (DWORD)write_size, &bytes_written, NULL);
		if (!bSuccess)
		{
			break;
		}
		need_write -= write_size;
	}
	CloseHandle(hWritePipe);//立即关闭写入段防止子进程阻塞
	//等待子进程结束
	WaitForSingleObject(pi.hProcess, INFINITE);
	// 关闭句柄
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	read_thread.join();
	CloseHandle(hReadPipe2);
}
#endif

#ifdef LINUX
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
void CGIExecuter::ExecuteCGI(std::string cgi_path, const std::string& query_string, const RbsLib::Network::TCP::TCPConnection& connection, const RbsLib::Network::HTTP::RequestHeader& header, const RbsLib::Buffer& buffer)
{
	int ptc[2], ctp[2];


	//设置子进程的环境变量在继承父进程的基础上增加HTTP请求头
	std::size_t env_size = 1;//=1 for last '\0'
	RbsLib::Network::HTTP::RequestHeader header_copy = header;
	//添加CGI环境变量到Headers
	std::string method;
	switch (header_copy.request_method)
	{
	case RbsLib::Network::HTTP::Method::GET:
		method = "GET";
		break;
	case RbsLib::Network::HTTP::Method::POST:
		method = "POST";
		break;
	default:
		method = "GET";
		break;
	}
	header_copy.headers.AddHeader("REQUEST_METHOD", method);
	if (!cgi_path.empty()) header_copy.headers.AddHeader("SCRIPT_NAME", cgi_path);
	if (!query_string.empty())header_copy.headers.AddHeader("QUERY_STRING", query_string);
	header_copy.headers.AddHeader("SERVER_NAME", Configuration::server_name);
	header_copy.headers.AddHeader("SERVER_PORT", std::to_string(Configuration::port));
	header_copy.headers.AddHeader("SERVER_PROTOCOL", "HTTP/1.1");
	header_copy.headers.AddHeader("SERVER_SOFTWARE", Configuration::server_version);
	header_copy.headers.AddHeader("REMOTE_ADDR", connection.GetAddress());


	//--------------------------------------------------------------------------------
	// 在此之后产生异常，可能导致资源无法正确释放，将可能产生异常的操作移至之前或使用try-catch捕获
	// 创建匿名管道 parent->child
	int result = pipe(ptc);
	if (result) {
		throw std::runtime_error("CreatePipe failed");
	}
	// child -> parent
	// 创建匿名管道 child->parent
	result = pipe(ctp);
	if (result) {
		close(ptc[0]);
		close(ptc[1]);
		throw std::runtime_error("CreatePipe failed");
	}

	// 创建子进程（例如启动一个控制台程序）
	pid_t pid;
	if ((pid = fork()) == 0)
	{
		//子进程
		// 这里申请的内存会在exec后自动释放，不需要手动释放
		//关闭无用端口
		close(ptc[1]);
		close(ctp[0]);
		//将管道的读取端作为子进程的标准输入
		if (dup2(ptc[0], STDIN_FILENO) == -1)
			exit(1);
		//将管道的写入端作为子进程的标准输出
		if (dup2(ctp[1], STDOUT_FILENO) == -1)
			exit(1);
		close(ptc[0]);
		close(ctp[1]);
		//忽略SIGPIPE信号
		signal(SIGPIPE, SIG_IGN);
		//构造环境变量
		char** env = new char* [header_copy.headers.GetHeaderMap().size() + 1];
		int i = 0;
		for (const auto& header : header_copy.headers.GetHeaderMap())
		{
			env[i] = new char[header.first.size() + header.second.size() + 2]; // +2 for '=' and '\0'
			strcpy(env[i], header.first.c_str());
			strcat(env[i], "=");
			strcat(env[i], header.second.c_str());
			i++;
		}
		env[i] = nullptr;
		char* args[] = { (char*)cgi_path.c_str(), NULL };
		execve(cgi_path.c_str(), args, env);
		exit(1);
	}
	else if (pid < 0)
	{
		close(ptc[0]);
		close(ptc[1]);
		close(ctp[0]);
		close(ctp[1]);
		throw std::runtime_error("fork failed");
	}
	else
	{
		close(ptc[0]);//关闭父进程的无用端口
		close(ctp[1]);
	}
	//关闭父进程的无用端口
	//创建一个线程来读取子进程的输出，并转发到浏览器
	std::thread read_thread([ctp, &connection,pid]() {
		try
		{
			//子线程不管理资源，因此无需考虑异常导致资源无法释放的问题
			RbsLib::Buffer buffer(64 * 1024);
			//读取HTTP头部
			//解析HTTP头部且拒绝HTTP的协议行，并获取Status行
				//在读取头部时，如果遇到连续的两个\r则合并为一个\r，这可能是因为CGI程序输出的\n被转换为\r\n
			//先读取整个HTTP头部，可能会读取部分HTTP响应体，但要保证能读取到完整的头部并放在buffer中
			while (buffer.GetLength() < buffer.GetSize())
			{
				std::size_t bytes_read;
				bytes_read = read(ctp[0], (char*)buffer.Data() + buffer.GetLength(), buffer.GetSize() - buffer.GetLength());
				if (bytes_read <= 0)
				{
					break;
				}
				buffer.SetLength(buffer.GetLength() + bytes_read);
				//退出循环时如果还没有读取到\r\n\r\n，则表示头部大小过大。
			}
			//解析头部
			int status = 0;//状态机，0表示位于key状态，1表示位于value状态，2表示位于行末\r状态，3表示位于行末\n状态,4位于key-value分隔符:状态，5表示位于额外的\r状态,6进入头部结尾状态,7表示位于头部结尾额外的\r状态，8表示完成状态
			std::string key;
			std::string value;
			bool error = false;
			RbsLib::Network::HTTP::ResponseHeader response;
			int content_start_pos;
			bool end = false;
			for (int i = 0; i < buffer.GetLength(); ++i)
			{
				if (error || end)
				{
					content_start_pos = i;
					break;
				}
				switch (status)
				{
				case 0:
					if (buffer[i] == '\r')
					{
						status = 6;
					}
					if (buffer[i] != ':')
						key.append(1, buffer[i]);
					else
					{
						if (key.empty())
						{
							error = true;
							break;
						}
						status = 4;
					}
					break;
				case 4:
					if (buffer[i] != ' ')
						error = true;
					else
						status = 1;
					break;
				case 1:
					if (buffer[i] != '\r')
						value.append(1, buffer[i]);
					else
					{
						if (value.empty())
						{
							error = true;
							break;
						}
						response.headers.AddHeader(key, value);
						key.clear();
						value.clear();
						status = 2;
					}
					break;
				case 2:
					if (buffer[i] == '\r')
					{
						//可能是CGI程序输出的\n被转换为\r\n
						status = 5;
					}
					else if (buffer[i] == '\n')
					{
						status = 0;
					}
					else
					{
						error = true;
						break;
					}
					break;
				case 5:
					if (buffer[i] == '\n')
					{
						status = 0;
					}
					else
					{
						error = true;
						break;
					}
					break;
				case 6:
					if (buffer[i] == '\n')
					{
						//头部读取结束
						end = true;
						status = 8;
					}
					else if (buffer[i] == '\r')
					{
						//可能是CGI程序输出的\n被转换为\r\n
						status = 7;
					}
					else
					{
						error = true;
					}
					break;
				case 7:
					if (buffer[i] == '\n')
					{
						//头部读取结束
						end = true;
						status = 8;
					}
					else
					{
						error = true;
					}
					break;
				}
			}
			//检查是否读取到完整的头部或是否存在错误
			if (error || status != 8)
			{
				error = true;//后续如果检查到error为true，则不向浏览器发送数据，但为了防止卡死子进程，继续读取管道数据
			}
			//检查是否存在Status行
			if (response.headers.ExistHeader("Status"))
			{
				//解析Status行
				std::string status_line = response.headers.GetHeader("Status");
				std::stringstream ss(status_line);
				std::string status_code;
				std::string status_description;
				std::getline(ss, status_code, ' ');
				std::getline(ss, status_description);
				if (status_code.empty())
				{
					error = true;
				}
				else
				{
					response.status = std::stoi(status_code);
					response.status_descraption = status_description;
				}
			}
			else
			{
				response.status = 200;
				response.status_descraption = "OK";
			}
			//发送buffer中剩余的数据
			if (error == 0)
			{
				connection.Send(response.ToBuffer());
				if (buffer.GetLength() > content_start_pos)
				{
					connection.Send((const char*)buffer.Data() + content_start_pos, buffer.GetLength() - content_start_pos);
				}
			}
			//继续读取管道数据并发送到浏览器
			while (true)
			{
				std::size_t bytes_read;
				bytes_read = read(ctp[0], (char*)buffer.Data(), buffer.GetSize());
				if (bytes_read <= 0)
				{
					break;
				}
				if (error == 0) connection.Send(buffer, bytes_read);
			}
			if (error)
			{
				//发送错误信息
				RbsLib::Network::HTTP::ResponseHeader response;
				response.status = 500;
				response.status_descraption = "Internal Server Error";
				response.headers.AddHeader("Content-Type", "text/html");
				response.headers.AddHeader("Connection", "close");
				std::string html = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1></body></html>";
				response.headers.AddHeader("Content-Length", std::to_string(html.size()));
				connection.Send(response.ToBuffer().AppendToEnd(RbsLib::Buffer(html)));
				//关闭子进程
				kill(pid, SIGKILL);
				Logger::LogError("CGI程序返回了错误的响应");
			}
		}
		catch (const std::exception&){}
		});

	// 父进程写入数据到管道（子进程通过stdin读取）
	std::size_t need_write = buffer.GetLength();
	while (need_write)
	{
		std::size_t write_size = buffer.GetLength() > need_write ? need_write : buffer.GetLength();
		std::size_t bytes_written;
		bytes_written = write(ptc[1], buffer.Data(),write_size);
		if (bytes_written<0)
		{
			break;
		}
		need_write -= write_size;
	}
	//立即关闭写入段防止子进程阻塞
	close(ptc[1]);
	//等待子进程结束
	int status;
	waitpid(pid, &status, 0);

	// 关闭句柄
	close(pid);
	read_thread.join();
	close(ctp[0]);
	//关闭读取端
	
}
#endif

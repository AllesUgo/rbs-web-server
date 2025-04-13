# RBS Web Server
RBS Web Server is a simple web server for serving static files,CGI program and handling basic HTTP requests.

It is built based on RBS Library and is designed to be lightweight and easy to use.

## How to Use
Clone the repository and run the server:
```bash
git clone https://github.com/AllesUgo/rbs-web-server.git
cd rbs-web-server
cmake -DCMAKE_BUILD_TYPE=Release .
make
```
Then run the server:
```bash
./http-server
```
Program will question you do you want to generate the config file on the first run.
If you answer yes, the config file will be generated in the current directory. You can edit it to change the server settings.

## Configuration
The server can be configured using a config file. The config file is in JSON format and can be edited to change the server settings.
The config like this:
```json
{
	"addr":	"0.0.0.0",
	"port":	80,
	"doc_root_path":	"./hdocs/",
	"server_name":	"RBS Web Server",
	"server_version":	"alpha v0.1",
	"cgi_path":	"./cgi/",
	"cgi_mapping_url":	"cgi-bin",
	"mime_path":	"./mime.json",
	"log_path":	"./log/",
	"default_page":	"index.html"
}
```
- addr: server bind address
- port: server bind port
- doc_root_path: document root path(folder where the static files are stored)
- server_name: server name
- server_version: server version
- cgi_path: cgi path(folder where the cgi programs are stored))
- cgi_mapping_url: cgi mapping url
- mime_path: mime type mapping file path(generated by the server and you can edit it)
- log_path: log path(folder where the log files are stored)
- default_page: default page name(when the user access the root url, the server will return this page, relative to doc root path)


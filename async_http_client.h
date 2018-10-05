#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/http/basic_parser.hpp>
#include <iostream>
#include <fstream>
#include <boost/array.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/beast.hpp>
#include <vector>
//------------------------------------------------------------------------------

// Performs an HTTP GET and prints the response
class AsyncHttpClient /*: public std::enable_shared_from_this<AsyncHttpClient>*/ {

  boost::beast::flat_buffer buffer_;
  //std::vector<char> chunk_buffer_; // 16kb
  char chunk_buffer_[16384];
  int count = 0;
  boost::beast::http::request<boost::beast::http::empty_body> req_;
  boost::beast::http::response_parser<boost::beast::http::string_body> res_;
  //boost::beast::http::response_parser<boost::beast::http::buffer_body> res_;

  boost::beast::http::response<boost::beast::http::string_body> cont_;

  // The io_context is required for all I/O
  boost::asio::io_context ioc_;
  // The SSL context is required, and holds certificates
  boost::asio::ssl::context ctx_{boost::asio::ssl::context::sslv23_client};

  //resolver_(ioc), stream_(ioc, ctx)

  boost::asio::ip::tcp::resolver resolver_{ioc_};
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_{ioc_, ctx_}; // https
  boost::asio::ip::tcp::socket socket_{ioc_}; // http

  bool https_mode_ = false;

  bool verifyCertificate(bool preverified, boost::asio::ssl::verify_context& ctx);

  // Report a failure
  void fail(boost::system::error_code ec, char const* what);

  std::ofstream file_;
  std::string file_name_;

  size_t content_size_ = 0;
  size_t total_load_ = 0;
  //./main -s http://master.qt.io -p 80 -t /archive/qt/5.10/5.10.1/submodules/qtwebengine-everywhere-src-5.10.1.tar.xz -o /tmp/archive3.tar.xz
  // http://master.qt.io/archive/qt/5.10/5.10.1/submodules/qtxmlpatterns-everywhere-src-5.10.1.zip


  std::string percentage2scale(unsigned int percentage);
public:
  // Resolver and stream require an io_context
  explicit AsyncHttpClient();

  // Start the asynchronous operation
  void run(char const* host, char const* port, char const* target, unsigned int version);

  void onResolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results);

  void onConnect(boost::system::error_code ec);

  void onHandshake(boost::system::error_code ec);

  void onWrite(boost::system::error_code ec, std::size_t bytes_transferred);

  void onRead(boost::system::error_code ec, std::size_t bytes_transferred);

  void onReadHeader(boost::system::error_code ec, std::size_t bytes_transferred);

  void onReadFull(boost::system::error_code ec, std::size_t bytes_transferred);

  void onShutdown(boost::system::error_code ec);

  void setFileName(const std::string &fileName);
};

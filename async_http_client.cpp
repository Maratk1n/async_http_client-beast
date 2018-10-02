#include "async_http_client.h"
#include <boost/regex.hpp>
#include <boost/bind.hpp>
#include <stdio.h>
#include <thread>
#include <boost/asio/read_until.hpp>
#include <boost/asio.hpp>

AsyncHttpClient::AsyncHttpClient()
{
  // Verify the remote server's certificate
  ctx_.set_verify_mode(boost::asio::ssl::verify_peer);

  ctx_.set_default_verify_paths();
}

void AsyncHttpClient::run(const char *host, const char *port, const char *target, unsigned int version)
{
  // Verify that we need to write to the file.
  if (!file_name_.empty()) {
    file_.open(file_name_);
  }
  // Check protocol
  std::string server(host);
  std::string protocol;
  boost::regex proto_exp(".+://");
  boost::smatch proto_what;
  if (boost::regex_search(server, proto_what, proto_exp)) {
    protocol = proto_what[0];
    server.erase(server.find(protocol), protocol.size());
    protocol.resize(protocol.size() - 3); // remove "://" delimeter
  }
  protocol = protocol.empty() ? "http" : protocol;
  if (protocol != "http" && protocol != "https") {
    throw std::runtime_error("Undefined protocol");
  }
  https_mode_ = protocol == "https" ? true : false;

  // Set SNI Hostname (many hosts need this to handshake successfully)
  if(https_mode_ && !SSL_set_tlsext_host_name(stream_.native_handle(), const_cast<char*>(server.c_str()))) {
    boost::system::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
    std::cerr << ec.message() << "\n";
    return;
  }


  // Set up an HTTP GET request message
  req_.version(version);
  req_.method(boost::beast::http::verb::get);
  req_.target(target);
  req_.set(boost::beast::http::field::host, server);
  req_.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  // Look up the domain name
  resolver_.async_resolve(server, port, std::bind(&AsyncHttpClient::onResolve, this, std::placeholders::_1, std::placeholders::_2));

  // Run the I/O service. The call will return when
  // the get operation is complete.
  ioc_.run();
}

void AsyncHttpClient::onResolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
{
  if(ec)
    return fail(ec, "resolve");

  // Make the connection on the IP address we get from a lookup
  if (https_mode_) {
    stream_.set_verify_mode(boost::asio::ssl::verify_peer);
    stream_.set_verify_callback(boost::bind(&AsyncHttpClient::verifyCertificate, this, _1, _2));
    boost::asio::async_connect(stream_.next_layer(), results.begin(), results.end(), std::bind( &AsyncHttpClient::onConnect, this, std::placeholders::_1));
  }
  else {
    boost::asio::async_connect(socket_, results.begin(), results.end(), std::bind(&AsyncHttpClient::onConnect, this, std::placeholders::_1));
  }
}

void AsyncHttpClient::onConnect(boost::system::error_code ec)
{
  if(ec)
    return fail(ec, "connect");

  if (https_mode_) {
    // Perform the SSL handshake
    stream_.async_handshake(boost::asio::ssl::stream_base::client, std::bind(&AsyncHttpClient::onHandshake, this, std::placeholders::_1));
  }
  else {
    // Send the HTTP request to the remote host
    boost::beast::http::async_write(socket_, req_, std::bind(&AsyncHttpClient::onWrite, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void AsyncHttpClient::onHandshake(boost::system::error_code ec)
{
  if(ec)
    return fail(ec, "handshake");

  // Send the HTTP request to the remote host
  boost::beast::http::async_write(stream_, req_, std::bind(&AsyncHttpClient::onWrite, this, std::placeholders::_1, std::placeholders::_2));
}

void AsyncHttpClient::onWrite(boost::system::error_code ec, std::size_t bytes_transferred)
{
  boost::ignore_unused(bytes_transferred);

  if(ec)
    return fail(ec, "write");

  if (https_mode_) {
    // Receive the HTTP response
    //boost::beast::http::async_read(stream_, buffer_, res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
    //boost::beast::http::async_read_header(stream_, buffer_, parser_, std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));
    //stream_.async_read_some(res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));

    //boost::asio::async_read_until(stream_, strbuf_, "\r\n\r\n", std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));
  }
  else {
    // Receive the HTTP response
    //boost::beast::http::async_read(socket_, buffer_, res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
    //socket_.async_read_some(boost::asio::buffer(buffer_, size_t(10)), std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
    //boost::beast::http::async_read_header(socket_, buffer_, parser_, std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));
    //socket_.async_read_some(boost::asio::buffer(buf_), std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));

    //boost::asio::async_read_until(socket_, strbuf_, "\r\n\r\n", std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));

    boost::beast::http::async_read_header(socket_, buffer_, header_parser_, std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void AsyncHttpClient::onRead(boost::system::error_code ec, std::size_t bytes_transferred)
{
  boost::ignore_unused(bytes_transferred);

  if(ec)
    return fail(ec, "read");

  // Write the message to standard out
  //std::cout << res_.base() << std::endl;

  //std::cout << buf_;
  for (int i = 0; i <= 100; i++) {
    std::cout << "Download: " << "[" << percentage2scale(i) << "] (" << i <<  "%)\r" << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  std::cout << std::endl;
  if (file_.is_open()) {
    file_ << res_.body();
    file_.close();
  }

  //socket_.async_read_some(boost::asio::buffer(buf_), std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
  //return;
  if (https_mode_) {
    // Gracefully close the stream
    stream_.async_shutdown(std::bind(&AsyncHttpClient::onShutdown, this, std::placeholders::_1));
  }
  else {
    // Gracefully close the socket
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    // not_connected happens sometimes so don't bother reporting it.
    if(ec && ec != boost::system::errc::not_connected)
        return fail(ec, "shutdown");

    // If we get here then the connection is closed gracefully
  }


}

void AsyncHttpClient::onReadHeader(boost::system::error_code ec, std::size_t bytes_transferred)
{
  boost::ignore_unused(bytes_transferred);

  std::cout << bytes_transferred << std::endl;
  //std::cout << boost::beast::buffers(strbuf_.data()) << std::endl;
//  if(ec)
//    return fail(ec, "read header");
  std::cout << "1" << std::endl;
  std::string header_{boost::asio::buffers_begin(strbuf_.data()), boost::asio::buffers_begin(strbuf_.data()) + static_cast<signed long>(bytes_transferred)};
  std::cout << header_ << std::endl;
//  boost::beast::error_code err_code;
//  boost::beast::http::request_parser<boost::beast::http::string_body> parser;
//  parser.put(boost::asio::buffer(header_), err_code);
//  if (err_code) {
//    return fail(err_code, "parse header");
//  }
//  std::cout << parser.content_length().value() << std::endl;

  std::string s =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "*****";
  boost::beast::error_code ec_;
  boost::beast::http::request_parser<boost::beast::http::empty_body> p;
  p.put(boost::asio::buffer(s), ec_);
  if (ec_) {
    return fail(ec_, "parse header");
  }
}

void AsyncHttpClient::onReadH(boost::system::error_code ec, std::size_t bytes_transferred)
{
  std::cout << bytes_transferred << std::endl;
  boost::ignore_unused(bytes_transferred);
  if(ec)
    return fail(ec, "read header");

}

void AsyncHttpClient::onShutdown(boost::system::error_code ec)
{
  if(ec == boost::asio::error::eof) {
    // Rationale:
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    ec.assign(0, ec.category());
  }
  if(ec)
    return fail(ec, "shutdown");

  // If we get here then the connection is closed gracefully
}

void AsyncHttpClient::setFileName(const std::string &fileName)
{
  file_name_ = fileName;
}

bool AsyncHttpClient::verifyCertificate(bool preverified, boost::asio::ssl::verify_context &ctx)
{
  // The verify callback can be used to check whether the certificate that is
  // being presented is valid for the peer. For example, RFC 2818 describes
  // the steps involved in doing this for HTTPS. Consult the OpenSSL
  // documentation for more details. Note that the callback is called once
  // for each certificate in the certificate chain, starting from the root
  // certificate authority.

  // In this example we will simply print the certificate's subject name.
  char subject_name[256];
  X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
  X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
  std::cout << "Verifying " << subject_name << std::endl;

  return preverified;
}

void AsyncHttpClient::fail(boost::system::error_code ec, const char *what)
{
  std::cerr << what << ": " << ec.message() << "\n";
}

std::string AsyncHttpClient::percentage2scale(unsigned int percentage)
{
  percentage = percentage > 100 ? 100 : percentage;
  unsigned int length = 50;
  std::string str;
  unsigned int border = static_cast<unsigned int>(length / 100.0f * percentage);
  for (unsigned int i = 0; i < length; i++) {
    if (i < border) {
      str += u8"▓";
    }
    else {
      str += ' ';
    }
  }
  return str;

}

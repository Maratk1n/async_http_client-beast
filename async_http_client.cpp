#include "async_http_client.h"
#include <boost/regex.hpp>
#include <boost/bind.hpp>
#include <stdio.h>
#include <thread>
#include <boost/asio/read_until.hpp>
#include <boost/asio.hpp>
#include <boost/format.hpp>

AsyncHttpClient::AsyncHttpClient()
{
  // Verify the remote server's certificate
  ctx_.set_verify_mode(boost::asio::ssl::verify_peer);

  ctx_.set_default_verify_paths();

  res_.body_limit(std::numeric_limits<std::uint64_t>::max());
}

void AsyncHttpClient::run(const char *host, const char *port, const char *target, unsigned int version)
{
  // Verify that we need to write to the file.
  if (!file_name_.empty()) {
    file_.open(file_name_, std::ios::out | std::ios::binary);
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
  if(ec) {
    return fail(ec, "connect");
  }

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
  if(ec) {
    return fail(ec, "handshake");
  }

  // Send the HTTP request to the remote host
  boost::beast::http::async_write(stream_, req_, std::bind(&AsyncHttpClient::onWrite, this, std::placeholders::_1, std::placeholders::_2));
}

void AsyncHttpClient::onWrite(boost::system::error_code ec, std::size_t bytes_transferred)
{
  boost::ignore_unused(bytes_transferred);

  if(ec) {
    return fail(ec, "write");
  }

  if (https_mode_) {
    // Receive the HTTP response
    boost::beast::http::async_read_header(stream_, buffer_, res_, std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));
  }
  else {
    // Receive the HTTP response
    boost::beast::http::async_read_header(socket_, buffer_, res_, std::bind(&AsyncHttpClient::onReadHeader, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void AsyncHttpClient::onReadHeader(boost::system::error_code ec, std::size_t bytes_transferred)
{
  boost::ignore_unused(bytes_transferred);

  if(ec) {
    return fail(ec, "read header");
  }
  content_size_ = res_.content_length().value();
  std::cout << res_.get().base() << std::endl;

  if (file_.is_open() && !res_.get().body().empty()) {
    file_ << res_.get().body();
  }

  // If we read the header, we can start reading content chunk by chunk.
  if (https_mode_) {
    // Receive the HTTP response
    boost::beast::http::async_read_some(stream_, buffer_, res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
  }
  else {
    // Receive the HTTP response
    boost::beast::http::async_read_some(socket_, buffer_, res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void AsyncHttpClient::onRead(boost::system::error_code ec, std::size_t bytes_transferred)
{
  boost::ignore_unused(bytes_transferred);
  total_load_ += bytes_transferred;

  if(ec && ec.value() != boost::asio::error::eof) {
    return fail(ec, "read content");
  }

  unsigned int percent = static_cast<unsigned int>(total_load_ * 100.0f / content_size_);
  if (ec.value() == boost::asio::error::eof) {
    percent = 100;
  }
  std::cout << "Download: " << "[" << percentage2scale(percent) << "] (" << percent <<  "%)\r" << std::flush;

  //if (ec.value() != boost::asio::error::eof) { // continue loading
  if (!res_.is_done()) { // continue loading
    if (file_.is_open()) {
      file_ << res_.get().body();
    }
    res_.release();
    if (https_mode_) {
      // Receive the HTTPS response
      boost::beast::http::async_read_some(stream_, buffer_, res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
    }
    else {
      // Receive the HTTP response
      boost::beast::http::async_read_some(socket_, buffer_, res_, std::bind(&AsyncHttpClient::onRead, this, std::placeholders::_1, std::placeholders::_2));
    }
  }
  else {
    if (file_.is_open()) {
      file_ << res_.get().body();
      file_.close();
    }
    std::cout << std::endl;
    std::cout << "Download completed." << std::endl;
    if (https_mode_) {
      // Gracefully close the stream
      stream_.async_shutdown(std::bind(&AsyncHttpClient::onShutdown, this, std::placeholders::_1));
    }
    else {
      // Gracefully close the socket
      socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      // not_connected happens sometimes so don't bother reporting it.
      if(ec && ec != boost::system::errc::not_connected) {
          return fail(ec, "shutdown");
      }
      // If we get here then the connection is closed gracefully
    }
  }

}

void AsyncHttpClient::onShutdown(boost::system::error_code ec)
{
  if(ec == boost::asio::error::eof) {
    // Rationale:
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    ec.assign(0, ec.category());
  }
  if(ec) {
    return fail(ec, "shutdown");
  }

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
  unsigned int length = 100;
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

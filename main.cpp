#include "async_http_client.h"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>

int main(int argc, char** argv) {
  // Check command line arguments.
  if(argc != 4 && argc != 5) {
    std::cerr <<
    "Usage: http-client-async-ssl <host> <port> <target> [<HTTP version: 1.0 or 1.1(default)>]\n" <<
    "Example:\n" <<
    "    http-client-async-ssl www.example.com 443 /\n" <<
    "    http-client-async-ssl www.example.com 443 / 1.0\n";
    return EXIT_FAILURE;
  }
  auto const host = argv[1];
  auto const port = argv[2];
  auto const target = argv[3];
  unsigned int version = argc == 5 && !std::strcmp("1.0", argv[4]) ? 10 : 11;

  // Launch the asynchronous operation
  std::make_shared<AsyncHttpClient>()->run(host, port, target, version);

  return EXIT_SUCCESS;
}

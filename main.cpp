#include "async_http_client.h"
#include <boost/program_options.hpp>

namespace po = boost::program_options;

int main(int argc, char** argv) {

  // examples
  //./main -s http://master.qt.io -p 80 -t /archive/qt/5.10/5.10.1/submodules/qtwebengine-everywhere-src-5.10.1.tar.xz -o /tmp/archive3.tar.xz
  // http://master.qt.io/archive/qt/5.10/5.10.1/submodules/qtxmlpatterns-everywhere-src-5.10.1.zip

  po::options_description desctiption("HTTP client options");

  desctiption.add_options()
      ("host,s", po::value<std::string>(), "Host, e.g.: localhost, http://example.com")
      ("port,p", po::value<std::string>(), "Port number")
      ("target,t", po::value<std::string>(), "Targer (at least '/')")
      ("http,H", po::value<std::string>(), "HTTP version, optional parameter (by default, version is 1.1)")
      ("output,o", po::value<std::string>(), "The output file path for recording the target. Optional parameter")
      ("help,h", "Show help");

  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desctiption).run(), vm);
  po::notify(vm);
  if (vm.count("help")) {
    std::cout << desctiption << std::endl;
    return EXIT_FAILURE;
  }
  if (!(vm.count("host") && vm.count("port") && vm.count("target"))) {
    std::cerr << "Wrong arguments. Use\n"
                 "./main --help\n"
                 "to get help.\n";
    return EXIT_FAILURE;
  }
  AsyncHttpClient client;
  if (vm.count("output")) {
    client.setFileName(vm["output"].as<std::string>());
  }
  unsigned int version = vm.count("http") && !std::strcmp("1.0", vm["http"].as<std::string>().c_str()) ? 10 : 11;
  // Launch the asynchronous operation
  client.run(vm["host"].as<std::string>().c_str(), vm["port"].as<std::string>().c_str(), vm["target"].as<std::string>().c_str(), version);

  return EXIT_SUCCESS;
}

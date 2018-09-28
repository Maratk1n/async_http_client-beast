#include "async_http_client.h"
#include <boost/program_options.hpp>

namespace po = boost::program_options;

int main(int argc, char** argv) {

  po::options_description desctiption("HTTP client options");

  std::string helper = std::string("List of parameters:\n"
                       "\t-h, --host\t\tHost, e.g.: localhost, http://example.com\n"
                       "\t-p, --port\t\tPort number\n"
                       "\t-t, --target\t\tTarger (at least '/')\n"
                       "\t-H, --http\t\tHTTP version, optional parameter (by default, version is 1.1)\n"
                       "\t-o, --output\t\tThe output file path for recording the target. Optional parameter\n"
                       "\t--help\t\t\tHelp\n");
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
  //std::make_shared<AsyncHttpClient>()->run(vm["host"].as<std::string>().c_str(), vm["port"].as<std::string>().c_str(), vm["target"].as<std::string>().c_str(), version);

  return EXIT_SUCCESS;
}

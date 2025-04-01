// Copyright (C) 2025 Evan McBroom
#include "cli.hpp"
#include "commands.hpp"
#include <clipp.h>
#include <codecvt>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <magic_enum.hpp>
#include <memory>
#include <replxx.hxx>
#include <spdlog/spdlog.h>
#include <thread>

namespace {
    // https://gist.github.com/EvanMcBroom/2a9bed888c2755153a9616aa7ae1f79a
    template<typename _T>
    unsigned int constexpr Hash(_T const* input) {
        return *input ? static_cast<unsigned int>(*input) + 33 * Hash(input + 1) : 5381;
    }

    void Help(Cli& cli, const std::string& args) {
        std::cout << "Please refer to the wiki for information about specific commands:" << std::endl
                  << "https://github.com/EvanMcBroom/lsa-whisperer/wiki" << std::endl;
    }

    template<typename PackageCall>
    auto CommandFactory(const std::shared_ptr<Lsa::Api>& lsa, PackageCall packageCall) {
        return [lsa, packageCall](Cli& cli, const std::string& input) {
            // Tokenize the user's input
            std::istringstream inputStream{ input };
            std::vector<std::string> tokens;
            std::copy(std::istream_iterator<std::string>(inputStream), std::istream_iterator<std::string>(), std::back_inserter(tokens));
            // Construct an equivalent to argv
            std::vector<char*> argv;
            std::for_each(tokens.begin(), tokens.end(), [&argv](const std::string& arg) {
                argv.push_back(const_cast<char*>(arg.data()));
            });
            try {
                packageCall(lsa, argv);
            } catch (const std::exception& exception) {
                std::cout << exception.what() << std::endl;
            }
        };
    }

    void History(Cli& cli, const std::string& args) {
        auto scan{ cli.history_scan() };
        for (size_t i{ 0 }; scan.next(); i++) {
            std::cout << std::setw(4) << i << ": " << scan.get().text() << std::endl;
        }
    }

    template<typename Enum>
    std::vector<std::string> SubCommands() {
        auto names{ magic_enum::enum_names<Enum>() };
        return std::vector<std::string>{ names.begin(), names.end() };
    }
}

int main(int argc, char** argv) {
    bool noHistory{ false };
    bool showHelp{ false };
    std::string historyFile{ "./.lsa_history.txt" };
    WCHAR applicationPath[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, applicationPath, MAX_PATH);
    std::string moduleDir{ (std::filesystem::path(applicationPath).parent_path() / "modules").string() };
    std::vector<std::string> commands;
    // clang-format off
    auto args = (
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
        clipp::option("--history-file").doc("Specify an alternative command line history file.") & clipp::value("path", historyFile),
        clipp::option("--module-dir").doc("Specify an alternative module directory.") & clipp::value("dir", moduleDir),
        clipp::option("--no-history").set(noHistory).doc("Do not create a command line history file."),
        clipp::opt_values("command", commands)
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return 0;
    }
    if (noHistory) {
        historyFile.clear();
    }
    spdlog::set_pattern("[%^%l%$] %v");
    auto lsa{ std::make_shared<Lsa::Api>(std::cout) };
    if (!commands.empty()) {
        // Process each commands
        for (auto& command : commands) {
            std::istringstream inputStream{ command };
            std::vector<std::string> tokens;
            std::copy(std::istream_iterator<std::string>(inputStream), std::istream_iterator<std::string>(), std::back_inserter(tokens));
            // Construct an equivalent to argv
            std::vector<char*> argv;
            std::for_each(tokens.begin(), tokens.end(), [&argv](const std::string& arg) {
                argv.push_back(const_cast<char*>(arg.data()));
            });
            // Pass the command to the appropriate handler
            switch (Hash(argv[0])) {
            case Hash("all"): AllPackages::Call(lsa, argv); break;
            case Hash("cloudap"): Cloudap::Call(lsa, argv); break;
            case Hash("kerberos"): Kerberos::Call(lsa, argv); break;
            case Hash("live"): Live::Call(lsa, argv); break;
            case Hash("msv1_0"): Msv1_0::Call(lsa, argv); break;
            case Hash("negoexts"): NegoExts::Call(lsa, argv); break;
            case Hash("negotiate"): Negotiate::Call(lsa, argv); break;
            case Hash("pku2u"): Pku2u::Call(lsa, argv); break;
            case Hash("schannel"): Schannel::Call(lsa, argv); break;
            case Hash("spm"): Spm::Call(lsa, argv); break;
            default:
                break;
            }
        }
    } else {
        // Start repl shell
        Cli cli{ historyFile };

        cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
            cli.clear_screen();
        });
        cli.AddCommand(".help", Help);
        cli.AddCommand(".history", History);
        cli.AddCommand(".log_level", [](Cli& cli, const std::string& args) {
            if (args.find(' ') == std::string::npos) {
                std::cout << "Log level: " << magic_enum::enum_name<spdlog::level::level_enum>(spdlog::get_level()) << std::endl;
            } else {
                try {
                    auto levelName{ args.substr(args.find(' ') + 1) };
                    spdlog::set_level(magic_enum::enum_cast<spdlog::level::level_enum>(levelName).value());
                } catch (...) {
                    spdlog::error("Please specify a valid log level.");
                }
            }
        });
        cli.AddSubCommandCompletions(".log_level", SubCommands<spdlog::level::level_enum>());
        cli.AddCommand("all", CommandFactory(lsa, AllPackages::Call));
        cli.AddCommand("cloudap", CommandFactory(lsa, Cloudap::Call));
        cli.AddCommand("kerberos", CommandFactory(lsa, Kerberos::Call));
        cli.AddCommand("live", CommandFactory(lsa, Live::Call));
        cli.AddCommand("msv1_0", CommandFactory(lsa, Msv1_0::Call));
        cli.AddCommand("negoexts", CommandFactory(lsa, NegoExts::Call));
        cli.AddCommand("negotiate", CommandFactory(lsa, Negotiate::Call));
        cli.AddCommand("pku2u", CommandFactory(lsa, Pku2u::Call));
        cli.AddCommand("schannel", CommandFactory(lsa, Schannel::Call));
        cli.AddCommand("spm", CommandFactory(lsa, Spm::Call));
        cli.AddExitCommand(".exit");
        cli.AddExitCommand(".quit");
        // Add autocompletions for each command's subcommands
        cli.AddSubCommandCompletions("all", SubCommands<AllPackages::PROTOCOL_MESSAGE_TYPE>());
        // Cloudap's subcommands are also handled directly to add the plugin commands for AAD and MSA
        auto cloudapAadMessages{ magic_enum::enum_names<Cloudap::Aad::CALL>() };
        auto cloudapMsaMessages{ magic_enum::enum_names<Cloudap::Msa::CALL>() };
        auto cloudapMessages(magic_enum::enum_names<Cloudap::PROTOCOL_MESSAGE_TYPE>());
        std::vector<std::string> cloudapSubCommands{ cloudapMessages.begin(), cloudapMessages.end() };
        cloudapSubCommands.insert(cloudapSubCommands.end(), cloudapAadMessages.begin(), cloudapAadMessages.end());
        cloudapSubCommands.insert(cloudapSubCommands.end(), cloudapMsaMessages.begin(), cloudapMsaMessages.end());
        cloudapSubCommands.erase(std::remove(cloudapSubCommands.begin(), cloudapSubCommands.end(), "CreateBindingKey"), cloudapSubCommands.end());
        cloudapSubCommands.erase(std::remove(cloudapSubCommands.begin(), cloudapSubCommands.end(), "GenerateBindingClaims"), cloudapSubCommands.end());
        cli.AddSubCommandCompletions("cloudap", cloudapSubCommands);
        cli.AddSubCommandCompletions("kerberos", SubCommands<Kerberos::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("live", SubCommands<Live::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("msv1_0", SubCommands<Msv1_0::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("negoexts", SubCommands<NegoExts::MESSAGE_TYPE>());
        auto negotiateMessages(magic_enum::enum_names<NEGOTIATE_MESSAGES>());
        std::vector<std::string> negotiateCommands{ negotiateMessages.begin(), negotiateMessages.end() };
        negotiateCommands.erase(std::remove(negotiateCommands.begin(), negotiateCommands.end(), "NegCallPackageMax"), negotiateCommands.end());
        cli.AddSubCommandCompletions("negotiate", negotiateCommands);
        cli.AddSubCommandCompletions("pku2u", SubCommands<Pku2u::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("schannel", SubCommands<Schannel::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("spm", SubCommands<SpmApi::NUMBER>());
        if (!moduleDir.empty() && std::filesystem::exists(moduleDir) && std::filesystem::is_directory(moduleDir)) {
            for (auto const& entry : std::filesystem::directory_iterator{ moduleDir, std::filesystem::directory_options::skip_permission_denied }) {
                auto ex = entry.path().extension();
                if (!entry.path().extension().compare(".dll")) {
                    cli.AddModule(entry.path().wstring());
                }
            }
        }
        cli.Start();
    }
    return 0;
}
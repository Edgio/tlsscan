//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    main.cc
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "def.h"
#include "conn.h"
#include "ndebug.h"
#include "host_info.h"
#include "missing_ciphersuites.h"
#include "tls_conn.h"
#include "scan.h"
//! ----------------------------------------------------------------------------
//! \details: sigint signal handler
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void sig_handler(int signo)
{
        if (signo == SIGINT)
        {
                //g_srvr->stop();
        }
}
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        // print out the version information
        fprintf(a_stream, "tlsscan tls/ssl protocol scanner.\n");
        fprintf(a_stream, "Copyright (C) Edgio Inc.\n");
        fprintf(a_stream, "               Version: %s\n", TLSSCAN_VERSION);
        fprintf(a_stream, "       OpenSSL Version: %s\n", SSLeay_version(SSLEAY_VERSION));
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: Print the command line help.
//! \return:  NA
//! \param:   a_stream FILE *
//! \param:   a_exit_code exit code
//! ----------------------------------------------------------------------------
static void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: tlsscan [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help                display this help and exit.\n");
        fprintf(a_stream, "  -V, --version             display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Run Options:\n");
        fprintf(a_stream, "  -4, --ipv4                resolve name to IPv4 address.\n");
        fprintf(a_stream, "  -6, --ipv6                resolve name to IPv6 address.\n");
        fprintf(a_stream, "  -t, --tls_options         TLS options string.\n");
        fprintf(a_stream, "  -c, --cert                check cert info.\n");
        fprintf(a_stream, "  -s, --ocsp                check OCSP response.\n");
        fprintf(a_stream, "  -a, --sig_algo            check signature algorithms.\n");
        fprintf(a_stream, "  -x, --curves              check elliptic curves.\n");
        fprintf(a_stream, "  -m, --compression         check for compression.\n");
        fprintf(a_stream, "  -e, --heartbleed          check for heartbleed.\n");
        fprintf(a_stream, "  -n, --servername          set TLS ext servername (SNI) in ClientHello.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Display Options:\n");
        fprintf(a_stream, "  -L, --show_client_ciphers show supported client ciphers.\n");
        fprintf(a_stream, "  -A, --show_cas            show trusted CA's for client auth.\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -G, --gprofile       Google cpu profiler output file\n");
        fprintf(a_stream, "  -H, --hprofile       Google heap profiler output file\n");
        fprintf(a_stream, "\n");
#endif
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details main
//! \return  0 on success
//!          -1 on error
//! \param   argc/argv...
//! ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // vars
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        std::string l_gprof_file;
        std::string l_hprof_file;
#endif
        int l_s;
        bool l_input_flag = false;
        std::string l_host;
        ns_tlsscan::scan_opt l_scan_opt;
        int l_ai_family = AF_UNSPEC;
        // -------------------------------------------------
        // Get args...
        // -------------------------------------------------
        char l_opt = '\0';
        std::string l_arg;
        int l_opt_index = 0;
        static struct option l_long_opt[] = {
                { "help",                no_argument,       0, 'h' },
                { "version",             no_argument,       0, 'V' },
                { "ipv4",                no_argument,       0, '4' },
                { "ipv6",                no_argument,       0, '6' },
                { "tls_options",         required_argument, 0, 't' },
                { "cert",                no_argument,       0, 'c' },
                { "ocsp",                no_argument,       0, 's' },
                { "sig_algo",            no_argument,       0, 'a' },
                { "curves",              no_argument,       0, 'x' },
                { "compression",         no_argument,       0, 'm' },
                { "heartbleed",          no_argument,       0, 'e' },
                { "servername",          required_argument, 0, 'n' },
                { "show_client_ciphers", no_argument,       0, 'L' },
                { "show_cas",            no_argument,       0, 'A' },
#ifdef ENABLE_PROFILER
                { "gprofile",            required_argument, 0, 'G' },
                { "hprofile",            required_argument, 0, 'H' },
#endif
                // Sentinel
                { 0,                     0,                 0,  0  }
        };
        // -------------------------------------------------
        // args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hV46t:csaxmen:LAG:H:";
#else
        char l_short_arg_list[] = "hV46t:csaxmen:LA";
#endif
        while(((unsigned char)l_opt != 255))
        {
                l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_opt, &l_opt_index);
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                switch (l_opt)
                {
                // -----------------------------------------
                // help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // version
                // -----------------------------------------
                case 'V':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // IPv4
                // -----------------------------------------
                case '4':
                {
                        l_ai_family = AF_INET;
                        break;
                }
                // -----------------------------------------
                // IPv6
                // -----------------------------------------
                case '6':
                {
                        l_ai_family = AF_INET6;
                        break;
                }
                // -----------------------------------------
                // tls options
                // -----------------------------------------
                case 't':
                {
                        int32_t l_s;
                        long l_tls_options;
                        l_s = ns_tlsscan::get_tls_options_str_val(l_arg, l_tls_options);
                        if(l_s != STATUS_OK)
                        {
                                fprintf(stdout, "error performing get_tls_options_str_val with string: %s.\n", l_arg.c_str());
                                return STATUS_ERROR;
                        }
                        l_scan_opt.m_tls_options = l_tls_options;
                        break;
                }
                // -----------------------------------------
                // cert
                // -----------------------------------------
                case 'c':
                {
                        l_scan_opt.m_show_cert = true;
                        break;
                }
                // -----------------------------------------
                // ocsp
                // -----------------------------------------
                case 's':
                {
                        l_scan_opt.m_check_ocsp_response = true;
                        break;
                }
                // -----------------------------------------
                // sig_algo
                // -----------------------------------------
                case 'a':
                {
                        l_scan_opt.m_check_sig_algo = true;
                        break;
                }
                // -----------------------------------------
                // curves
                // -----------------------------------------
                case 'x':
                {
                        l_scan_opt.m_check_groups = true;
                        break;
                }
                // -----------------------------------------
                // compression
                // -----------------------------------------
                case 'm':
                {
                        l_scan_opt.m_check_compression = true;
                        break;
                }
                // -----------------------------------------
                // heartbleed
                // -----------------------------------------
                case 'e':
                {
                        l_scan_opt.m_check_heartbleed = true;
                        break;
                }
                // -----------------------------------------
                // servername
                // -----------------------------------------
                case 'n':
                {
                        l_scan_opt.m_servername = l_arg;
                        break;
                }
                // -----------------------------------------
                // show_client_ciphers
                // -----------------------------------------
                case 'L':
                {
                        l_scan_opt.m_show_client_ciphers = true;
                        break;
                }
                // -----------------------------------------
                // show_cas
                // -----------------------------------------
                case 'A':
                {
                        l_scan_opt.m_show_trust_ca = true;
                        break;
                }
#ifdef ENABLE_PROFILER
                // -----------------------------------------
                // google cpu profiler output file
                // -----------------------------------------
                case 'G':
                {
                        l_gprof_file = optarg;
                        break;
                }
#endif
#ifdef ENABLE_PROFILER
                // -----------------------------------------
                // google heap profiler output file
                // -----------------------------------------
                case 'H':
                {
                        l_hprof_file = optarg;
                        break;
                }
#endif
                // -----------------------------------------
                // ?
                // -----------------------------------------
                case '?':
                {
                        // ---------------------------------
                        // Required argument was missing
                        // '?' is provided when the 3rd arg
                        // to getopt_long does not begin with
                        //':', and preceeded by an automatic
                        // error message.
                        // ---------------------------------
                        fprintf(stdout, "  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        // ---------------------------------
                        // get the host...
                        // ---------------------------------
                        if(argv[optind])
                        {
                                l_host = argv[optind];
                        }
                        if(!l_host.empty())
                        {
                                l_input_flag = true;
                        }
                        else
                        {
                                fprintf(stdout, "Unrecognized option.\n");
                                print_usage(stdout, -1);
                        }
                        break;
                }
                }
        }
        // -------------------------------------------------
        // verify input
        // -------------------------------------------------
        if(!l_input_flag)
        {
                fprintf(stdout, "error: host required.");
                print_usage(stdout, -1);
        }
        // -------------------------------------------------
        // check for port
        // -------------------------------------------------
        l_scan_opt.m_port = 443;
        std::string l_host_str = l_host;
        size_t l_end = l_host_str.find(':');
        if(l_end != std::string::npos)
        {
                size_t l_start = 0U;
                std::string l_port_str;
                uint16_t l_port = 443;
                l_host     = l_host_str.substr(l_start, l_end - l_start);
                l_port_str = l_host_str.substr(l_host.length()+1, l_end);
                l_port = (uint16_t)strtoul(l_port_str.c_str(), NULL, 10);
                l_scan_opt.m_port = l_port;
        }
        if(l_host.empty())
        {
                fprintf(stdout, "error: host: %s malformed.", l_host_str.c_str());
                print_usage(stdout, -1);
        }
        // -------------------------------------------------
        // init...
        // -------------------------------------------------
        SSL_library_init();
        //SSLeay_add_all_algorithms();
        ERR_load_crypto_strings();
        // -------------------------------------------------
        // init...
        // find missing ciphers
        // build the list of ciphers missing from OpenSSL.
        // -------------------------------------------------
        ns_tlsscan::get_missing_ciphers();
        // -------------------------------------------------
        // resolve
        // -------------------------------------------------
        ns_tlsscan::host_info l_host_info;
        l_s = ns_tlsscan::lookup(l_host, l_scan_opt.m_port, l_host_info, l_ai_family);
        if(l_s != STATUS_OK)
        {
                goto cleanup;
        }
        //l_host_info.show();
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        {
        ns_tlsscan::conn l_conn(l_host_info);
        l_s = l_conn.connect();
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("failed to connect...\n");
                goto cleanup;
        }
        // -------------------------------------------------
        // show connected address
        // -------------------------------------------------
        char l_host_str[NI_MAXHOST] = "";
        char l_port_str[NI_MAXSERV] = "";
        int32_t l_s;
        l_s = getnameinfo((struct sockaddr *)&l_host_info.m_sa,
                          sizeof(struct sockaddr_storage),
                          l_host_str,
                          sizeof(l_host_str),
                          l_port_str,
                          sizeof(l_port_str),
                          NI_NUMERICHOST | NI_NUMERICSERV);
        if (l_s != 0)
        {
                // TODO???
        }
        printf("%sConnected to %s:%s%s\n\n",
                ANSI_COLOR_FG_GREEN,
                l_host_str,
                l_port_str,
                ANSI_COLOR_OFF);
        }
        // -------------------------------------------------
        // override host
        // -------------------------------------------------
        if (!l_scan_opt.m_servername.empty())
        {
             l_host_info.m_host = l_scan_opt.m_servername;
        }
        // -------------------------------------------------
        // scan host
        // -------------------------------------------------
        l_s = scan_host(l_host_info, l_scan_opt);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("failed to scan...\n");
                goto cleanup;
        }
        // -------------------------------------------------
        // cleanup...
        // -------------------------------------------------
cleanup:
        // ???
        return STATUS_OK;
}

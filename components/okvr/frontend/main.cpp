#include "volePSI/fileBased.h"
#include "cryptoTools/Common/Log.h"
#include "perf.h"

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv);

    if (cmd.isSet("perf"))
    {
        perf(cmd);
    }
    else if (cmd.isSet("balls"))
    {
        overflow(cmd);
    }
    else
    {
        std::cout << oc::Color::Green << "Benchmark programs: \n"
                  << oc::Color::Default
                  << "   -perf: required flag to run benchmarking\n"
                  << "   -paxos: Run the okvs benchmark.\n"
                  << "      -n <value>: The set size. Can also set n using -nn wher n=2^nn.\n"
                  << "      -t <value>: the number of trials.\n"
                  << "      -b <value>: The bitcount of the index type. Must by a multiple of 8 and greater than 1.3*n.\n"
                  << "      -v: verbose.\n"
                  << "      -w <value>: The okvs weight.\n"
                  << "      -ssp <value>: statistical security parameter.\n"
                  << "      -binary: binary okvs dense columns.\n"
                  << "      -cols: The size of the okvs elemenst in multiples of 16 bytes. default = 1.\n"
                  << "   -baxos: The the bin okvs benchmark. Same parameters as -paxos plus.\n"
                  << "      -lbs <value>: the log2 bin size.\n"
                  << "      -nt: number of threads.\n";

        std::cout << oc::Color::Green << "Unit tests: \n"
                  << oc::Color::Default
                  << "   -u: Run all of the unit tests.\n"
                  << "   -u -list: List run all of the unit tests.\n"
                  << "   -u 10 15: Run unit test 10 and 15.\n"
                  << "   -u 10..15: Run unit test 10 to 15 (exclusive).\n"
                  << "   -u psi: Run unit test that contain \"psi\" is the title.\n\n";
    }

    return 0;
}
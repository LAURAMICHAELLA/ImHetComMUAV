#ifndef IRIS_H
#define IRIS_H
#include <string>

struct Iris {
    float tam_packet;
    float throughput;
    float signal;
    float SNR;
    std::string weight_class;


};


enum Iris_Class
{
   short_packet,
   mediumsize_packet,
   large_packet,
   unknown
};
#endif

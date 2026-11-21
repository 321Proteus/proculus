// Dummy gateway service: placeholder for the REST API / RBAC entry point.
#include <iostream>

#include "proculus/version.h"

int main() {
    std::cout << "proculus gateway v" << proculus_version() << " (dummy service)\n";
    return 0;
}

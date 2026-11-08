#include "common.h"
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Verifying Attack Engine logic...\n");
    
    // Test with small duration and 1 thread to check for crashes
    printf("Testing UDP...\n");
    p2p_udp_attack_start("127.0.0.1", 9999, 1, 512, 1, 1);
    
    printf("Testing TCP RAW...\n");
    p2p_tcp_raw_attack_start("127.0.0.1", 9999, 1, 1, 0, 1);
    
    printf("Testing HTTP...\n");
    p2p_http_attack_start("127.0.0.1", 9999, 1, 1, 1);
    
    printf("Testing GRE...\n");
    p2p_gre_attack_start("127.0.0.1", 1, 0, 1);
    
    printf("Testing App...\n");
    p2p_app_attack_start("127.0.0.1", 9999, 1, 1);
    
    printf("Testing ICMP...\n");
    p2p_icmp_attack_start("127.0.0.1", 1, 1);
    
    printf("Testing Game...\n");
    p2p_game_udp_attack_start("127.0.0.1", 9999, 1, 0, 1);
    
    printf("Waiting for threads to launch...\n");
    sleep(2);
    printf("Verification complete. No crashes detected.\n");
    return 0;
}

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    //char *genCMT(uint64_t value, char *sn_string, char *r_string);

    char *genClaimproof(uint64_t value_s,
                        char *sn_s_string,
                        char *r_s_string,
                        char *cmt_s_string,
                        uint64_t value_c,
                        char *r_c_string,
                        char *cmt_c_string,
                        uint64_t L,
                        uint64_t N
                    );

    bool verifyClaimproof(char *data, 
                        char *cmtS_string, 
                        char *cmtC_string, 
                        uint64_t L, 
                        uint64_t N
                    );

#ifdef __cplusplus
} // extern "C"
#endif
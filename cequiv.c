#include <stdlib.h>
#include <stdio.h>


typedef struct {
    unsigned int reg_v0;
    unsigned int reg_v1;
} two_int_return;

two_int_return DecryptAndCheck(unsigned int message_word,
                               unsigned int key){
    two_int_return results;
    int i;
    unsigned int shifting_word, check_result, word_to_reverse;
    results.reg_v1 = message_word ^ key;
    shifting_word = results.reg_v1;
    for (i=0;i<4;i++){
        check_result = shifting_word & 255;
        printf("check_result is %d\n", check_result);
        if (check_result < 64 || check_result > 90){
            results.reg_v0 = 0;
            return results;
        }
        shifting_word = shifting_word >> 8;
    }
    results.reg_v0 = 1;
    return results;
}

typedef struct {
    unsigned int reg_v0;
    unsigned int *reg_v1;
} int_and_addr;



int_and_addr RecursiveDecryptAndPlace(unsigned int* orig_string_location,
                                      unsigned int* decrypt_string_location,
                                      unsigned int key){
    int_and_addr results;
    two_int_return decrypt_result;
    printf("Recursing osval: %u\n", *orig_string_location);
    unsigned int bitmask = 255;
    printf("With mask: %u\n", *orig_string_location & bitmask);
    if ((*orig_string_location & bitmask)==0){
        printf("BASE\n");
        results.reg_v0 = 1;
        results.reg_v1  = decrypt_string_location;
        return results;
    }
    decrypt_result = DecryptAndCheck(*orig_string_location,key);
    if (decrypt_result.reg_v0){
        results = RecursiveDecryptAndPlace(orig_string_location+1,
                                             decrypt_string_location, key);

        if (!results.reg_v0){
            return results; // this forces abort 
        }
        
        *(results.reg_v1) = decrypt_result.reg_v1;
        results.reg_v1++;
        return results;
    }
    
    results.reg_v0 = 0;
    return results;
}

int main(int argc, char **argv){
    unsigned int key;
    unsigned int key_base = (unsigned int) atoi(argv[1]);
    char decrypted_message[1000];
    int_and_addr result;
    key = key_base + (key_base<<8) + (key_base<<16) + (key_base<<24);
    result = RecursiveDecryptAndPlace((unsigned int*) argv[2],
                                      (unsigned int*) decrypted_message,
                                      key);
    if (result.reg_v0){
        printf("Decryption success\n");
        printf("%s decripts to %s\n",
               argv[2], decrypted_message);
    }
    return 1;
}



    
    



        
        
    
    
        

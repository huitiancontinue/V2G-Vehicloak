#include <stdio.h>
#include <iostream>

#include "uint256.h"
#include "convertcgo.cpp"

using namespace std;

int main () {

    uint64_t value = uint64_t(14);
    char* sn = "123";
    char* r = "123";
    //char* cmt = genCMT(value, sn, r);
    //cout<<cmt<<endl;
    char* cmt = "36cae1252931ddb004764cd91695ca434b38f9cbcc96b2dabb7f915aab1c891b";
    uint64_t value_old = uint64_t(22); 
    char* sn_old = "123";
    char* r_old = "123";
    // char* cmt_old = genCMT(value_old, sn_old, r_old);
    // cout<<cmt_old<<endl;
    char* cmt_old = "9edf793da5108894702617981e8f74667948a926041562dc9b4e2a7730042aeb";
    uint64_t values = uint64_t(8);
    char* sns = "123";
    char* rs = "123";
    // char* cmts = genCMT(values, sns, rs);
    // cout<<cmts<<endl;
    char* cmts = "14c15fb90479f8836423db8aec1eb9cbd234d2e6d1883731ee8b2240977b51f7";
    
    // char* proof = genConvertproof(value_old, sns, rs, sn_old, r_old, cmts, cmt_old, values, value, sn, r, cmt);
    // cout<<proof<<endl;
    char* proof = "14bf57a6ad7632fc9dc965440d1c8deaa60a7f3f2fc5530d79a7d81a1f7526621369fdd997f662b854c08afc142c7edee517275b86075f515ca543ea6afccd760cf8e86ad9b20f2e1b0f69dd8b33048185bcc17930a70cdbd68d512c4108a800096213287946801111819ea4f7e17e0fae518aa2b188801ec5febe9a125d72ed1380c122813a75fd37719091ba52de9959c7f551d08508460a1c8f419b97272b18f172daf36c71e8a692e3ae40d7274de182eb5c71954ee9b81d7d9c6c3acc3f1745a21d010051ae921cd1d55728dc3058a2d29fd04a390556043b4aaa3a6ab02ca2acd17da4549082ca5bc855c2d06d78cf8059c981e964a6fac62ea7e4d33f2f42c7671f51b59eeaa6192e8db1dbf8fbcec7b76f4024a443ac86b7339d2c2919f25805b4be6e4f239aaab163f2daa84b8d2bcfedc49c15ee30bd6ea2de1888192d0bb608f21c0245dd8d7b6d161a7e2b5d84eeb0bcd24635f830c632de1e9016f7634e192c6bf521a3dbb2cd1b5bcfb5e42af2d65309b1196df04fadba9ca6256778a6f9df7a122d33a4ee77f8c616ce26acd91b45fec85e968459062200a70321397b6bff0d131c3b74ddbee8fb13b606df50f5e31b0cedc1122d1200f2a601f6f092513a6749124f6fbc2613ed1cd6d950fb496b24aa2b36d7603268f0bf1907541fbe1ecf6648801dfdf3fa263590d609517db25651018204887c7f73141453abdc78272f07e1ab1e7c2fee9818af27e05819338e5c7f88adb881714d1720c686d600ba778ba53bb4864431a6f8c3592d362e64d21abaa05064d8258921";
    bool b = verifyConvertproof(proof, cmt_old, sn_old, cmts, cmt);
    if(!b){
        cout<<"Wrong Proof!"<<endl;
    }else{
        cout<<"Right Proof!"<<endl;
    }
    
    return 0;
}
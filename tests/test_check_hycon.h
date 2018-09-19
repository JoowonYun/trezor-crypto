START_TEST(test_bip32_hycon_hdnode)
{
	HDNode node;

	uint8_t seed[66];
	mnemonic_to_seed("ring crime symptom enough erupt lady behave ramp apart settle citizen junk", "", seed, 0);
    hdnode_from_seed(seed, 64, SECP256K1_NAME, &node);

    ck_assert_mem_eq(seed,  fromhex("f377694f59ca0f152a8623bb218cf30b8512c068fc73cf10263e3f62881726d0356979d3d1751b80596203b5f3f2c5fe002fb2321dcec8b0d4b043de791cca07"), 64);
	ck_assert_mem_eq(node.chain_code,  fromhex("4777e377abba7e7e1f3376a148f878122dd48df77d2a8ec520e78d87dfcd489a"), 32);
	ck_assert_mem_eq(node.private_key, fromhex("b0131e72be2d6935cc46992ae30fe9d5ec859df20e2985a3d77e94a0ebb39ab3"), 32);
    hdnode_fill_public_key(&node);
    ck_assert_mem_eq(node.public_key, fromhex("03c041b71ba82a539d2462464abf7bcf9dffb5950a27f7bcb71850fc8a69a418b1"), 33);

    hdnode_private_ckd_prime(&node, 44);
    hdnode_private_ckd_prime(&node, 1397);
    hdnode_private_ckd_prime(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_fill_public_key(&node);
    ck_assert_mem_eq(node.private_key, fromhex("f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2"), 32);
    ck_assert_mem_eq(node.public_key, fromhex("02c4199d83e47650b854e027188eade5378d19c94c13b226f43310fb144bc224af"), 33);

    size_t hash_length = 32;
    uint8_t output[hash_length];
    blake2b(node.public_key, 33, output, hash_length);
    ck_assert_mem_eq(output, fromhex("dafec57d0062e2317f6d0f294366e2a531a891233fd59cfa5f062a0f1018af6a"), hash_length);

    size_t address_array_length = 20;
    uint8_t address_array[address_array_length];
    size_t start_index = hash_length - address_array_length;
    for(size_t i=start_index; i<hash_length; ++i) {
        address_array[i - start_index] = output[i];
    }
    ck_assert_mem_eq(address_array, fromhex("4366e2a531a891233fd59cfa5f062a0f1018af6a"), address_array_length);

    size_t address_length = 28;
    char address[address_length];
    memset(address, 0, address_length);
    b58enc(address, &address_length, address_array, address_array_length);
    ck_assert_str_eq(address, "wTsQGpbicAZsXcmSHN8XmcNR9wX");

    
    uint8_t hash[hash_length];
    blake2b(address_array, address_array_length, hash, hash_length);
    ck_assert_mem_eq(hash, fromhex("0454038bfa9d19b1649b3978334a325d6feddcc345f4523fd8712182295278a9"), hash_length);

    size_t checksum_all_length = 44;
    char checksum_all[checksum_all_length];
    memset(checksum_all, 0, checksum_all_length);
    b58enc(checksum_all, &checksum_all_length, hash, hash_length);
    ck_assert_str_eq(checksum_all, "Htw7r9y6XHp26UbBx19Dn1hMF6V7niXHjR5vUNZdwvG");

    size_t checksum_length = 5;
    char checksum[checksum_length];
    memset(checksum, 0, checksum_length);
    memcpy(checksum, checksum_all, checksum_length-1);
    ck_assert_str_eq(checksum, "Htw7");

    size_t address_str_length = 33;
    char address_str[address_str_length];
    memset(address_str, 0, address_str_length);
    address_str[0] = 'H';
    memcpy(address_str + 1, address, address_length-1);
    memcpy(address_str + address_length, checksum, checksum_length -1);
    ck_assert_str_eq(address_str, "HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7");
}
END_TEST

#include "protob/hyconTx.pb-c.h"

START_TEST(test_hycon_sign)
{
    size_t address_array_length = 20;

    uint8_t from_address_array[address_array_length];
    b58tobin(from_address_array, &address_array_length, "wTsQGpbicAZsXcmSHN8XmcNR9wX");
    ck_assert_mem_eq(from_address_array, fromhex("4366e2a531a891233fd59cfa5f062a0f1018af6a"), address_array_length);
    ProtobufCBinaryData from_address;
    from_address.len = address_array_length;
    from_address.data = from_address_array;


    uint8_t to_address_array[address_array_length];
    b58tobin(to_address_array, &address_array_length, "3GKJpnAXne7iGBLjmHQLFQxpJU8A");
    ck_assert_mem_eq(to_address_array, fromhex("a28306b5066c6f94d903bc2aae4f7b025ca19823"), address_array_length);
    ProtobufCBinaryData to_address;
    to_address.len = address_array_length;
    to_address.data = to_address_array;

    HyconTx tx = HYCON_TX__INIT;
    tx.to =  to_address;
    tx.from = from_address;
    tx.nonce = 2;
    tx.amount = 0;
    tx.fee = 0;

    uint8_t* buf;
    buf = malloc(hycon_tx__get_packed_size(&tx));
    // hycon_tx__pack(&tx, buf);
    
    
}
END_TEST
#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <seal/seal.h>
#include <iostream>
using namespace std::chrono;
using namespace std;
using namespace seal;


int qtest1();
int qtest2();
// For this test, we need the parameters to be such that the number of
// compressed ciphertexts needed is 1.
int main()
{
    qtest1();
    //qtest2();
    return 0;
}
int qtest1() {

    uint64_t number_of_items = 128*2;
    uint64_t size_per_item = 1; // in bytes
    uint32_t N = 4096*4;
    int block = 128;
    uint32_t num_kw = pow(2, 16);
    uint32_t num_index = pow(2, 18);
    int num_pt = ceil(double(num_index)/ (N * 4));
    //cout << num_pt << endl;
    
    int num_bucket = 6;
    number_of_items = number_of_items * num_bucket;
    int num_hash = 3;
    
    // Recommended values: (logt, d) = (12, 2) or (8, 1).
    uint32_t logt = 20;
    uint32_t d = 1;

    EncryptionParameters enc_params(scheme_type::bfv);
    PirParams pir_params;

    // Generates all parameters

    cout << "Main: Generating SEAL parameters" << endl;
    gen_encryption_params(N, logt, enc_params);

    cout << "Main: Verifying SEAL parameters" << endl;
    verify_encryption_params(enc_params);
    cout << "Main: SEAL parameters are good" << endl;

    cout << "Main: Generating PIR parameters" << endl;
    gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params);

    // gen_params(number_of_items, size_per_item, N, logt, d, enc_params,
    // pir_params);
    print_pir_params(pir_params);

    KeyGenerator keygen(enc_params);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    PIRServer server(enc_params, pir_params);

    // Initialize PIR client....
    PIRClient client(enc_params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    // Set galois key for client with id 0
    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    random_device rd;
    // Choose an index of an element in the DB
    uint64_t ele_index =
        rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index);   // index of FV plaintext第几个密文
    //uint64_t offset = client.get_fv_offset(ele_index); // offset in FV plaintext第几个槽位
    //cout << "Main: element index = " << ele_index << " from [0, "
    //    << number_of_items - 1 << "]" << endl;
    //cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;
    
    // measure query generation
    //auto time_query_s = high_resolution_clock::now();
    //PirQuery query = client.generate_query(118);//typedef std::vector<std::vector<seal::ciphertext>> pirquery;
    //auto time_query_e = high_resolution_clock::now();
    //auto time_query_us =
    //    duration_cast<microseconds>(time_query_e - time_query_s).count();
    //cout << "main: query generated" << endl;

    // Measure query generation
    //uint64_t ele[] = { 1,10,100,101,102,1000 };
    
    uint64_t ele[] = { 1,10,100,101,102,200 };
    //uint64_t ele[] = {1};
    int size = sizeof(ele)/sizeof(ele[0]);
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_querys(ele,size, enc_params);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us =
    duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << time_query_us << "微秒" << endl;
    /*uint64_t index2 = index + 2;
    PirQuery query2 = client.generate_query(index2);
    Ciphertext query0;
    Evaluator evaluator(enc_params);
    evaluator.add_inplace(query[0][0], query2[0][0]);*/
    // 打开一个二进制文件流用于写入
    ostringstream out;
    query[0][0].save(out);
    size_t actual_size = out.str().size();

    cout<<"查询密文大小"<< actual_size /1024.0<< "K字节" << endl;
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    uint64_t n_i = pir_params.nvec[0];
    vector<Ciphertext> expanded_query = server.expand_query(query[0][0], n_i, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
        duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "Main: query expanded: " << time_server_us << "微秒" << endl;
    //delete query;
    int expand = time_server_us;
    assert(expanded_query.size() == n_i);

    Evaluator evaluator(enc_params);
    //evaluator.multiply_inplace(expanded_query[1], expanded_query[10]);
    //evaluator.add_inplace(expanded_query[1], expanded_query[10]);

    cout << "Main: checking expansion" << endl;
    for (size_t i = 0; i < expanded_query.size(); i++) {
        Plaintext decryption = client.decrypt(expanded_query.at(i));

        if (decryption.is_zero() ) {
            continue;
        }
        else if (decryption.is_zero()) {
            cout << "Found zero where index should be" << endl;
            return -1;
        }
        else if (std::stoi(decryption.to_string()) != 1) {
            cout << "Query vector at index " << index
                << " should be 1 but is instead " << decryption.to_string() << endl;
            return -1;
        }
        else {
            cout << "Query vector at index " << i << " is "
                << decryption.to_string() << endl;
        }
    }

    BatchEncoder batch_encoder(enc_params);
    //Enccoder 
    Plaintext pt2("3");
    Ciphertext ct2 = client.Enc(pt2);
    vector<uint64_t> pod_matrix(N, 0ULL);
    pod_matrix[0] = 1ULL;
    pod_matrix[1] = 2ULL;
    pod_matrix[2] = 3ULL;
    pod_matrix[3] = 4ULL;
    pod_matrix[4] = 5ULL;
    //evaluator.mu
    Plaintext pt;
    batch_encoder.encode(pod_matrix, pt);
    Ciphertext ct= client.Enc(pt);
    Ciphertext a;
    //Ciphertext ans;
    auto start = high_resolution_clock::now();
    //evaluator.multiply_plain_inplace(ct, pt2);
    auto end = high_resolution_clock::now();
    auto use =
        duration_cast<microseconds>(end - start).count();
    //cout << "批密文乘单个明文: " << use << "微秒" << endl;
    std::vector<seal::Ciphertext> b(block);
    start = high_resolution_clock::now();
    for (int i = 0; i < block; i++)
    {
        //evaluator.multiply_plain(expanded_query[i], pt, b[i]);
        evaluator.multiply_plain(ct, pt, b[i]);
    }
    evaluator.add_many(b, a);
    //evaluator.add_many(b,ans);
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    cout << "解码: " << use<< "微秒" << endl;
    cout << "解码: " << use*(double(num_index) / (N * 4)) *num_hash*(num_kw/block) << "微秒" << endl;
    int decode = use*num_hash * num_kw / block;
    std::vector<seal::Ciphertext> c(num_kw /block,a);
    start = high_resolution_clock::now();
    for(int i=0;i< (num_kw*num_hash) /(block*num_bucket);i++)
    {
        evaluator.multiply_inplace(c[i], expanded_query[1]);
    }
    evaluator.add_many(c, a);
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    cout << "二次选择: " << use * num_pt * num_bucket << "微秒" << endl;
    int ch2 = use;
    std::vector<seal::Ciphertext> ans(num_bucket,a);
    Ciphertext ans2;
    Ciphertext ans3;
    start = high_resolution_clock::now();
    for (int i = 0; i < num_bucket; i++)
    {
        evaluator.multiply_inplace(ans[i], ans[i]);
        //evaluator.relinearize_inplace(a, relin_keys);
    }

    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    int si = use;
    cout << "交集: " << use* num_pt << "微秒" << endl;
    
    
    //evaluator.multiply(c[0], c[1], ans3);
    //evaluator.multiply_inplace(ans2, c[1]);
    /*start = high_resolution_clock::now();
    evaluator.multiply_plain_inplace(ct, pt);
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    cout << "批明文乘批量密文: " << use << "微秒" << endl;*/

    
    
    Plaintext decryption1 = client.decrypt(a);
    evaluator.relinearize_inplace(a, relin_keys);
    evaluator.mod_switch_to_next_inplace(a);
    ostringstream out1;
    a.save(out1);
    actual_size = out1.str().size();
    cout << "回复密文大小" << actual_size / 1024.0 << "K字节" << endl;
    //cout << "回复密文大小" << sizeof(a) << "字节" << endl;
    batch_encoder.decode(decryption1, pod_matrix);
    cout << "解密"<<endl<<pod_matrix[0] << endl;

    for (int i = 0; i < 10; i++)
    {
        cout << pod_matrix[i + 1]<<endl;
    }
    
    //pt[0] = 1;
   // auto start = high_resolution_clock::now();
   //// evaluator.multiply_plain_inplace(expanded_query[1], pt2);
   // auto end = high_resolution_clock::now();
   // auto use =
   //     duration_cast<microseconds>(end - start).count();
   // cout << "一次明文乘密文乘积: " << use << "微秒" << endl;
   /* start = high_resolution_clock::now();
    evaluator.multiply_inplace(expanded_query[1], expanded_query[1]);*/
    //evaluator.multiply_inplace(expanded_query[10], expanded_query[10]);
   /* for (int i = 0; i < 3; i++)
    {
        evaluator.add_inplace(expanded_query[1], expanded_query[1]);
    }*/
    
    /*end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    cout << "一次密文文乘密文乘积: " << use << "微秒" << endl;*/
   /* Plaintext decryption = client.decrypt(expanded_query.at(1));
    cout << "Query vector at index " << 1 << " is "
        << decryption.to_string() << endl;*/
    return 1;

   
}
int qtest2()
{
    uint64_t number_of_items = 1024;
    uint64_t size_per_item = 1; // in bytes
    uint32_t N = 4096 * 4;
    int m = 2;
    uint32_t num_kw = pow(2, 11);
    uint32_t num_index = pow(2, 12);
    int num_pt = ceil(double(num_index) / (N * 4));
    //cout << num_pt << endl;
    number_of_items = number_of_items * m;
   
    // Recommended values: (logt, d) = (12, 2) or (8, 1).
    uint32_t logt = 20;
    uint32_t d = 1;

    EncryptionParameters enc_params(scheme_type::bfv);
    PirParams pir_params;

    // Generates all parameters

    cout << "Main: Generating SEAL parameters" << endl;
    gen_encryption_params(N, logt, enc_params);

    cout << "Main: Verifying SEAL parameters" << endl;
    verify_encryption_params(enc_params);
    cout << "Main: SEAL parameters are good" << endl;

    cout << "Main: Generating PIR parameters" << endl;
    gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params);

    // gen_params(number_of_items, size_per_item, N, logt, d, enc_params,
    // pir_params);
    print_pir_params(pir_params);

    KeyGenerator keygen(enc_params);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    PIRServer server(enc_params, pir_params);

    // Initialize PIR client....
    PIRClient client(enc_params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    // Set galois key for client with id 0
    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    

    // Measure query generation
    //uint64_t ele[] = { 1,10,100,101,102,1000 };

    uint64_t ele[] = { 1,10,100,101,102,200 };
    //uint64_t ele[] = {1};
    int size = sizeof(ele) / sizeof(ele[0]);
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_querys(ele, size, enc_params);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us =
        duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << time_query_us << "微秒" << endl;
   
    ostringstream out;
    query[0][0].save(out);
    size_t actual_size = out.str().size();

    cout << "查询密文大小" << actual_size / 1024.0 << "K字节" << endl;
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    uint64_t n_i = pir_params.nvec[0];
    vector<Ciphertext> expanded_query = server.expand_query(query[0][0], n_i, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
        duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "密文扩展: " << time_server_us/1000 << "毫秒" << endl;
    uint64_t expand = time_server_us;
    assert(expanded_query.size() == n_i);

    Evaluator evaluator(enc_params);
    //evaluator.multiply_inplace(expanded_query[1], expanded_query[10]);
    //evaluator.add_inplace(expanded_query[1], expanded_query[10]);

    cout << "Main: checking expansion" << endl;
    for (size_t i = 0; i < expanded_query.size(); i++) {
        Plaintext decryption = client.decrypt(expanded_query.at(i));

        if (decryption.is_zero()) {
            continue;
        }
        else if (decryption.is_zero()) {
            cout << "Found zero where index should be" << endl;
            return -1;
        }
        else if (std::stoi(decryption.to_string()) != 1) {
            cout << "Query vector at index " << i
                << " should be 1 but is instead " << decryption.to_string() << endl;
            return -1;
        }
        else {
            cout << "Query vector at index " << i << " is "
                << decryption.to_string() << endl;
        }
    }
    BatchEncoder batch_encoder(enc_params);
    vector<uint64_t> pod_matrix(N, 0ULL);
    pod_matrix[0] = 1ULL;
    pod_matrix[1] = 2ULL;
    pod_matrix[2] = 3ULL;
    pod_matrix[3] = 4ULL;
    pod_matrix[4] = 5ULL;
    Plaintext pt;
    
    batch_encoder.encode(pod_matrix, pt);
    Ciphertext ct = client.Enc(pt);
    Ciphertext ct2;
    Ciphertext ct3;
    auto start = high_resolution_clock::now();
    for (int i = 0; i < 2; i++)
    {
        evaluator.multiply_inplace(expanded_query[i], expanded_query[i+1]);
    }
    auto end = high_resolution_clock::now();
    auto use =
        duration_cast<microseconds>(end - start).count();
    cout << "比较所有kw: " << (use * num_kw*m)/1000 << "毫秒" << endl;
    uint64_t eq_kw = use * num_kw*m;
    start = high_resolution_clock::now();
    for (int i = 0; i < 8; i++)
    {
        evaluator.add_inplace(expanded_query[i], expanded_query[i+1]);
    }
    for (int i = 0; i < m; i++)
    {
        evaluator.multiply_inplace(expanded_query[i], expanded_query[i + 1]);
    }
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    uint64_t vec = use * num_index;
    cout << "生成01向量: " << (use * num_index) / 1000 << "毫秒" << endl;
    start = high_resolution_clock::now();
    evaluator.multiply_plain(expanded_query[1],pt,ct2);
    evaluator.add_inplace(ct2, ct2);
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    uint64_t vec2 = use * num_index;
    cout << "打包: " << (use * num_index) / 1000 << "毫秒" << endl;
    //evaluator.multiply_plain(ct2, pt, ct3);
    cout<<"总时间"<<(expand+eq_kw+vec+vec2)/1000<< "毫秒" << endl;
    



    return 0;
}

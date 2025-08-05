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

    uint64_t number_of_expand = 128*2;
    uint64_t size_per_item = 1;
    uint32_t N = 4096*4;
    int block = 128;
    uint32_t num_kw = pow(2, 16);
    uint32_t num_index = pow(2, 18);
    int num_pt = ceil(double(num_index)/ (N * 4)); 
    int num_bucket = 6;
    number_of_expand = number_of_expand * num_bucket;
    int num_hash = 3;   
    uint32_t logt = 20;
    uint32_t d = 1;
    EncryptionParameters enc_params(scheme_type::bfv);
    PirParams pir_params;

    gen_encryption_params(N, logt, enc_params);

    verify_encryption_params(enc_params);
  
    gen_pir_params(number_of_expand, size_per_item, d, enc_params, pir_params);
    
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
    int size = sizeof(ele)/sizeof(ele[0]);
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_querys(ele,size, enc_params);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us =
    duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "query_generated" << time_query_us/pow(10,6) << "s" << endl;
    ostringstream out;
    query[0][0].save(out);
    size_t actual_size = out.str().size();
    cout<<"ct_size"<< actual_size /1024.0<< "KB" << endl;
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    uint64_t n_i = pir_params.nvec[0];
    vector<Ciphertext> expanded_query = server.expand_query(query[0][0], n_i, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
    duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "ct_expanded: " << time_server_us / pow(10, 6) << "s" << endl;
    //delete query;
    int expand = time_server_us;
    assert(expanded_query.size() == n_i);
    Evaluator evaluator(enc_params);
    cout << "checking expansion" << endl;
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
    
    std::vector<seal::Ciphertext> b(block);
    start = high_resolution_clock::now();
    for (int i = 0; i < block; i++)
    {
        evaluator.multiply_plain(expanded_query[i], pt, b[i]);
    }
    evaluator.add_many(b, a);
    //evaluator.add_many(b,ans);
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    cout << "ln_decode: " << use*(double(num_index) / (N * 4)) *num_hash*(num_kw/block)/ pow(10,6) << "s" << endl;
    //int decode = use*num_hash * num_kw / block;
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
    cout << "sd_choice: " << use * num_pt * num_bucket/ pow(10, 6) << "s" << endl;
    
    std::vector<seal::Ciphertext> ans(num_bucket,a);
    
    start = high_resolution_clock::now();
    for (int i = 0; i < num_bucket-1; i++)
    {
        evaluator.multiply_inplace(ans[0], ans[i+1]);
        evaluator.relinearize_inplace(ans[0], relin_keys);
    }
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    int si = use;
    cout << "set_it: " << use* num_pt/pow(10,6) << "s" << endl;
    Plaintext decryption1 = client.decrypt(a);
    evaluator.relinearize_inplace(a, relin_keys);
    evaluator.mod_switch_to_next_inplace(a);
    ostringstream out1;
    a.save(out1);
    actual_size = out1.str().size();
    cout << "CT_ANS_SIZE" << actual_size / 1024.0 << "KB" << endl;
    
    batch_encoder.decode(decryption1, pod_matrix);
    cout << "DECODE"<<endl<<pod_matrix[0] << endl;
    for (int i = 0; i < 10; i++)
    {
        cout << pod_matrix[i + 1]<<endl;
    }
    
    return 1;

   
}
int qtest2()
{
    uint64_t number_of_expand = 1024;
    uint64_t size_per_item = 1; 
    uint32_t N = 4096 * 4;
    int m = 2;
    uint32_t num_kw = pow(2, 11);
    uint32_t num_index = pow(2, 12);
    int num_pt = ceil(double(num_index) / (N * 4));
    number_of_expand = number_of_expand * m;
    uint32_t logt = 20;
    uint32_t d = 1;
    EncryptionParameters enc_params(scheme_type::bfv);
    PirParams pir_params;
    gen_encryption_params(N, logt, enc_params);
    verify_encryption_params(enc_params); 
    gen_pir_params(number_of_expand, size_per_item, d, enc_params, pir_params);
    print_pir_params(pir_params);
    KeyGenerator keygen(enc_params);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);   
    PIRServer server(enc_params, pir_params);
    PIRClient client(enc_params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();
    server.set_galois_key(0, galois_keys);
    uint64_t ele[] = { 1,10 };
    //uint64_t ele[] = {1};
    int size = sizeof(ele) / sizeof(ele[0]);
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_querys(ele, size, enc_params);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us =
        duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "query_generated" << time_query_us/pow(10,6) << "s" << endl;
   
    ostringstream out;
    query[0][0].save(out);
    size_t actual_size = out.str().size();

    cout << "ct_size" << actual_size / 1024.0 << "KB" << endl;
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    uint64_t n_i = pir_params.nvec[0];
    vector<Ciphertext> expanded_query = server.expand_query(query[0][0], n_i, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
        duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "ct_expand:" << time_server_us / pow(10, 6) << "s" << endl;
    uint64_t expand = time_server_us;
    assert(expanded_query.size() == n_i);

    Evaluator evaluator(enc_params);
    
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
    cout << "kw_eq_all: " << (use * num_kw*m)/pow(10,6)<< "s" << endl;
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
    cout << "gen_01_vector: " << (use * num_index) / pow(10, 6) << "s" << endl;
    start = high_resolution_clock::now();
    evaluator.multiply_plain(expanded_query[1],pt,ct2);
    evaluator.add_inplace(ct2, ct2);
    end = high_resolution_clock::now();
    use =
        duration_cast<microseconds>(end - start).count();
    uint64_t vec2 = use * num_index;
    cout << "pack: " << (use * num_index) / pow(10, 6) << "s" << endl;
    
    



    return 0;
}

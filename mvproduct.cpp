
#include "header.h"

using namespace std;
using namespace seal;


void example_mvproduct(){
    // TODO implement

    int dim = 4;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    EncryptionParameters parms(scheme_type::CKKS);


    vector<int> moduli(4, 40);
    moduli[0] = 50; 
    moduli[moduli.size() - 1] = 59;

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
    poly_modulus_degree, moduli));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

        cout << "Generating keys...";
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    GaloisKeys galois_keys = keygen.galois_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    cout << "...done " << endl;

    // generate random 4*4 matrix and size-4 vector. 

    vector<vector<double> > M(dim); 
    vector<double> v(dim); 
    for (int i = 0;  i < M.size(); i++){
        M[i].resize(dim); 
        for (int j = 0; j < dim; j++ ){
            M[i][j] = (double)rand() / RAND_MAX;
            v[j] = (double)rand() / RAND_MAX;
        }
    }

    // plaintext computation 
    vector<double> Mv(dim,0);
    for (int i = 0;  i < M.size(); i++){
        for (int j = 0; j < dim; j++){
            Mv[i] += M[i][j] * v[j]; 
        }
    }



    // Encode the diagonals
    vector<Plaintext> ptxt_diag(dim); 
    Plaintext ptxt_vec; 
    for (int i = 0; i < dim; i++){
        vector<double> diag(dim); 
        for (int j = 0; j < dim; j++){
            diag[j] = M[j][(j+i) % dim]; 
        }
        encoder.encode(diag, scale, ptxt_diag[i]); 
    }
 
    // repeat the v. 
    vector<double> vrep(encoder.slot_count()); 
    for (int i = 0; i < vrep.size(); i++) vrep[i] = v[i % v.size()]; 
    encoder.encode(vrep, scale, ptxt_vec);

    Ciphertext ctv; 
    encryptor.encrypt(ptxt_vec, ctv); 

    // Generate the galois keys
    

    // Now: perform the multiplication 
    Ciphertext temp; 
    Ciphertext enc_result; 
    for (int i =0; i < dim ; i++){
            // rotate 
            evaluator.rotate_vector(ctv, i, galois_keys, temp);  
            // multiply
            evaluator.multiply_plain_inplace(temp, ptxt_diag[i]); 
            if (i == 0){
                enc_result = temp; 
            }else{
                evaluator.add_inplace(enc_result, temp); 
            }
    }

    Plaintext plain_result;
    vector<double> result;
 

    decryptor.decrypt(enc_result, plain_result); 
    encoder.decode(plain_result, result); 

    for (int i = 0; i < dim; i++){
        cout << "actual: " << result[i] << ", expected: " << Mv[i] << endl; 
    }

    // validation

}
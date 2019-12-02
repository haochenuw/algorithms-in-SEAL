
#include "header.h"

using namespace std;
using namespace seal;

void example_polyeval_horner(int degree);
void example_polyeval_tree(int degree);
void example_polyeval_bsgs(int degree);

// dotproduct between a vector of ctxt and a vector of ptxt. 
void dot_product(vector<Plaintext> &pts, int skip, const vector<Ciphertext> &ctx, 
                Evaluator &evaluator, Ciphertext &destination); 

void compute_all_powers(const Ciphertext &ctx, int degree, Evaluator &evaluator, RelinKeys &relin_keys, vector<Ciphertext> &powers){



    powers.resize(degree+1); 
    powers[1] = ctx; 

    vector<int> levels(degree +1, 0);
    levels[1] = 0;
    levels[0] = 0;


    for (int i = 2; i <= degree; i++){
        // compute x^i 
        int minlevel = i;
        int cand = -1; 
        for (int j = 1; j <= i/2; j++){
            int k =  i - j; 
            //
            int newlevel = max(levels[j], levels[k]) + 1;
            if( newlevel < minlevel){
                cand = j;
                minlevel = newlevel;
            }
        }
        levels[i] = minlevel; 
        // use cand 
        if (cand < 0) throw runtime_error("error"); 
        //cout << "levels " << i << " = " << levels[i] << endl; 
        // cand <= i - cand by definition 
        Ciphertext temp = powers[cand]; 
        evaluator.mod_switch_to_inplace(temp, powers[i-cand].parms_id()); 
        
        evaluator.multiply(temp, powers[i-cand], powers[i]);
        evaluator.relinearize_inplace(powers[i], relin_keys);  
        evaluator.rescale_to_next_inplace(powers[i]); 
    }
    return; 
} 



void example_polyeval() {
    cout << "Example: Polynomial Evaluation" << endl;

    cout << "Enter degree: "; 
    int degree = 0; 
    cin >> degree; 

    if (degree != 15){
        throw invalid_argument("degree not supported by this sample code now. ");
    }


    while (true)
    {
        cout << endl;
        cout << "Select a method" << endl;
        cout << "  1. Horner's method" << endl;
        cout << "  2. Tree evaluation" << endl;
        cout << "  3. Tree evaluation plus bstep-gstep" << endl;
        cout << "  0. Quit" << endl;

        int selection = 0;
        // cout << endl << "> Run performance test (1 ~ 4) or go back (0): ";
        if (!(cin >> selection))
        {
            cout << "Invalid option." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }

        switch (selection)
        {
        case 1:
            example_polyeval_horner(degree);
            break;

        case 2:
            example_polyeval_tree(degree);
            break;

        case 3:
            example_polyeval_bsgs(degree);
            break;
        case 0:
            cout << endl;
            return;

        default:
            cout << "Invalid option." << endl;
        }
    }
}


void example_polyeval_tree(int degree){

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;


    EncryptionParameters parms(scheme_type::CKKS);

    int depth = ceil(log2(degree));

    vector<int> moduli(depth + 4, 40);
    moduli[0] = 50; 
    moduli[moduli.size() - 1] = 59;


    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, moduli));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    cout << "Generating keys...";
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    cout << "...done " << endl;

    // generate random for 



    // generate random input.
    double x = 1.1;
    Plaintext ptx; 
    encoder.encode(x, scale, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);
    cout << "x = " << x << endl;



    vector<double> coeffs(degree + 1); 

    vector<Plaintext> plain_coeffs(degree+1);

    cout << "Poly = ";
    for (size_t i = 0; i < degree + 1; i++) {
        coeffs[i] = (double)rand() / RAND_MAX;
        encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << coeffs[i] << ", "; 
    }
    cout << endl;

    cout << "encryption done " << endl;


    Plaintext plain_result;
    vector<double> result;
    //decryptor.decrypt(ctx, plain_result);
    //encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;


    double expected_result = coeffs[degree];
    


    // compute all powers
    vector<Ciphertext> powers(degree+1); 
    
    time_start = chrono::high_resolution_clock::now();
       
    compute_all_powers(ctx, degree, evaluator, relin_keys, powers); 
    cout << "All powers computed " << endl; 

    Ciphertext enc_result;
    // result =a[0]
    encryptor.encrypt(plain_coeffs[0], enc_result); 

    Ciphertext temp; 

    /*
    for (int i = 1; i <= degree; i++){
        decryptor.decrypt(powers[i], plain_result);
        encoder.decode(plain_result, result);
        // cout << "power  = " << result[0] << endl;
    }
    */

    // result += a[i]*x[i]
    for (int i = 1; i <= degree; i++){  

        //cout << i << "-th sum started" << endl; 
        evaluator.mod_switch_to_inplace(plain_coeffs[i], powers[i].parms_id()); 
        evaluator.multiply_plain(powers[i], plain_coeffs[i], temp); 
        evaluator.rescale_to_next_inplace(temp); 
        //cout << "got here " << endl; 
        evaluator.mod_switch_to_inplace(enc_result, temp.parms_id()); 
        enc_result.scale() = pow(2.0, 40); 
        temp.scale() = pow(2.0, 40); 
        evaluator.add_inplace(enc_result, temp);
        // cout << i << "-th sum done" << endl; 
    }
   time_end = chrono::high_resolution_clock::now();
   time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
   cout << "Done [" << time_diff.count() << " microseconds]" << endl;
   



    for (int i = degree - 1; i >= 0; i--) {      
        expected_result *= x; 
        expected_result += coeffs[i]; 
    }
    cout << "evaluation done" << endl;

    decryptor.decrypt(enc_result, plain_result);
    encoder.decode(plain_result, result);

   
    cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << endl;




}


void example_polyeval_horner(int degree) {

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    EncryptionParameters parms(scheme_type::CKKS);

    vector<int> moduli(degree + 4, 40);
    moduli[0] = 50; 
    moduli[moduli.size() - 1] = 59;


    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, moduli));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    cout << "Generating keys...";
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    cout << "...done " << endl;

    // generate random for 



    // generate random input.
    double x = 1.1;
    Plaintext ptx; 
    encoder.encode(x, scale, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);
    cout << "x = " << x << endl;



    vector<double> coeffs(degree + 1); 

    vector<Plaintext> plain_coeffs(degree+1);

    cout << "Poly = ";
    for (size_t i = 0; i < degree + 1; i++) {
        coeffs[i] = (double)rand() / RAND_MAX;
        encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << coeffs[i] << ", "; 
    }
    cout << endl;



    time_start = chrono::high_resolution_clock::now();

    Ciphertext temp; 
    encryptor.encrypt(plain_coeffs[degree], temp);

    cout << "encryption done " << endl;


    Plaintext plain_result;
    vector<double> result;
    //decryptor.decrypt(ctx, plain_result);
    //encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;


    double expected_result = coeffs[degree];
    

    for (int i = degree - 1; i >= 0; i--) {
       
        
        // temp*= x
        expected_result *= x; 
        evaluator.mod_switch_to_inplace(ctx, temp.parms_id());
        evaluator.multiply_inplace(temp, ctx);

        /*
        decryptor.decrypt(temp, plain_result);
        encoder.decode(plain_result, result);
        cout << "temp2 = " << result[0] << endl;
        */

        evaluator.relinearize_inplace(temp, relin_keys);

        //decryptor.decrypt(temp, plain_result);
        //encoder.decode(plain_result, result);
        //cout << "temp after relin = " << result[0] << endl;


        evaluator.rescale_to_next_inplace(temp); 

        //decryptor.decrypt(temp, plain_result);
        //encoder.decode(plain_result, result);
        //cout << "temp1  = " << result[0] << endl;

        
        // temp += a[i]
        expected_result += coeffs[i]; 

        evaluator.mod_switch_to_inplace(plain_coeffs[i], temp.parms_id());
        
        temp.scale() = pow(2.0, 40); // manually reset the scale
        evaluator.add_plain_inplace(temp, plain_coeffs[i]);

        //cout << i << "-th iteration done" << endl;

        //decryptor.decrypt(temp, plain_result);
        //encoder.decode(plain_result, result);
        //cout << "temp = " << result[0] << endl;

    }
   time_end = chrono::high_resolution_clock::now();
   time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
   cout << "Done [" << time_diff.count() << " microseconds]" << endl;
   

    cout << "evaluation done" << endl;


    decryptor.decrypt(temp, plain_result);
    encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;

   
    cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << endl;


}

void example_polyeval_bsgs(int degree){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    EncryptionParameters parms(scheme_type::CKKS);

    int depth = ceil(log2(degree));

    vector<int> moduli(depth + 4, 40);
    moduli[0] = 50; 
    moduli[moduli.size() - 1] = 59;


    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, moduli));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    cout << "Generating keys...";
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    cout << "...done " << endl;

    double x = 1.1;
    Plaintext ptx; 
    encoder.encode(x, scale, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);
    cout << "x = " << x << endl;

    if (degree != 15) {
        throw invalid_argument("not implemented");
    }
    int n1 = 4; 
    int n2 = 4; 

    vector<double> coeffs(degree + 1); 

    vector<Plaintext> plain_coeffs(degree+1);

    cout << "Poly = ";
    for (size_t i = 0; i < degree + 1; i++) {
        coeffs[i] = (double)rand() / RAND_MAX;
        encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << coeffs[i] << ", "; 
    }
    cout << endl;
    cout << "encryption done " << endl;


    Plaintext plain_result;
    vector<double> result;
    //decryptor.decrypt(ctx, plain_result);
    //encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;

    
    // compute the expected result. 
    double expected_result = coeffs[degree];
    for (int i = degree - 1; i >= 0; i--) {      
        expected_result *= x; 
        expected_result += coeffs[i]; 
    }


    vector<Ciphertext> powers_bs(n1+1); 
    vector<Ciphertext> powers_gs(n2); 


    time_start = chrono::high_resolution_clock::now();
    compute_all_powers(ctx, n1, evaluator, relin_keys, powers_bs); 



    cout << "bs done" << endl;
    compute_all_powers(powers_bs[n1], n2, evaluator, relin_keys, powers_gs); 
    cout << "gs done" << endl;

    powers_bs.pop_back(); // remove last

    Ciphertext result_ctxt; 

    for (int j = 0; j < n2; j++){
        // cout << j << "-th iter started" << endl;

        Ciphertext temp; 
        // (vec, skip)
        dot_product(plain_coeffs, j*n1, powers_bs, evaluator, temp); 

        // temp *= x^{jn1}
        // result += temp; 
        if (j > 0){
            // need to decide which. 
            if (temp.coeff_mod_count() > powers_gs[j].coeff_mod_count()){
                evaluator.mod_switch_to_inplace(temp, powers_gs[j].parms_id());         
            } else if (temp.coeff_mod_count() < powers_gs[j].coeff_mod_count()){
                evaluator.mod_switch_to_inplace(powers_gs[j], temp.parms_id());         
            }
            evaluator.multiply_inplace(temp, powers_gs[j]); 
            evaluator.rescale_to_next_inplace(temp); 
            evaluator.mod_switch_to_inplace(result_ctxt, temp.parms_id()); 

            temp.scale() = result_ctxt.scale(); 
            evaluator.add_inplace(result_ctxt, temp); 
        }
        else{
            result_ctxt = temp; 
        }
        //cout << j << "-th iter done" << endl;
    }

    //cout << "evaluation done" << endl;
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
  
    decryptor.decrypt(result_ctxt, plain_result);
    encoder.decode(plain_result, result);

   
    cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << endl;



    // Final validation 
}

void dot_product(vector<Plaintext> &pts, int skip, const vector<Ciphertext> &ctx, 
                Evaluator &evaluator, Ciphertext &destination){

    Ciphertext temp; 

    //cout << "skip = " << skip << endl; 

    for (int i = 1; i < ctx.size();i++){

        evaluator.mod_switch_to_inplace(pts[i+skip], ctx[i].parms_id()); 
        evaluator.multiply_plain(ctx[i], pts[i+skip], temp); 
        if (i == 1){
            destination = temp; 
        } else{
            evaluator.mod_switch_to_inplace(destination, temp.parms_id()); 
            // cout << "scales : " << temp.scale() << ", " << destination.scale() << endl;
            temp.scale() = destination.scale(); 
            evaluator.add_inplace(destination, temp); 
        }
    }
    evaluator.rescale_to_next_inplace(destination); 

    evaluator.mod_switch_to_inplace(pts[skip], destination.parms_id()); 

    // manually set scale right. 
    destination.scale() = pts[skip].scale(); 
    evaluator.add_plain_inplace(destination, pts[skip]); 



    return; 
}
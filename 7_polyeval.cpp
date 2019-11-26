
#include "polyeval.h"

using namespace std;
using namespace seal;

void example_polyeval_horner(int degree);


void example_polyeval() {
    cout << "Example: Polynomial Evaluation" << endl;

    cout << "Enter degree: " << endl; 
    int degree = 0; 
    cin >> degree; 


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
            //example_polyeval_tree();
            break;

        case 3:
            //example_polyeval_bsgs();
            break;
        case 0:
            cout << endl;
            return;

        default:
            cout << "Invalid option." << endl;
        }
    }
}

void example_polyeval_horner(int degree) {

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
    cout << "evaluation done" << endl;


  
   
    cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << endl;


}
# Algorithms in SEAL 
Some example algorithms for homomorphic encryption computation based on Microsoft SEAL. 

## Running the examples

First, install SEAL 3.4.0 from https://github.com/Microsoft/SEAL. 

Then
```
cmake .
make
```
will create two executables in the `bin` directory. `mvproduct` is for matrix-vector multiplication, and `polyeval` does polynomial evaluation. 

 



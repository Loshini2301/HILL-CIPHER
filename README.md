# EX. NO: 3 
# HILL CIPHER
## NAME:LOSHINI G
## REGISTER NO:212223220051
## DEPARTMENT:IT

## AIM:
  IMPLEMENTATION OF HILL CIPHER.
  To write a C program to implement the hill cipher substitution techniques.

## DESCRIPTION:

Each letter is represented by a number modulo 26. Often the simple scheme A = 0, B
= 1... Z = 25, is used, but this is not an essential feature of the cipher. To encrypt a message, each block of n letters is  multiplied by an invertible n × n matrix, against modulus 26. To
decrypt the message, each block is multiplied by the inverse of the m trix used for
 
encryption. The matrix used
 
for encryption is the cipher key, and it sho
 
ld be chosen
 
randomly from the set of invertible n × n matrices (modulo 26).


## ALGORITHM:

#### STEP-1:
Read the plain text and key from the user.
#### STEP-2: 
Split the plain text into groups of length three. 
#### STEP-3: 
Arrange the keyword in a 3*3 matrix.
#### STEP-4: 
Multiply the two matrices to obtain the cipher text of length three.
#### STEP-5:
Combine all these groups to get the complete cipher text.

## PROGRAM :
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S 3

int mod26(int x) {
    x %= 26;
    if (x < 0) x += 26;
    return x;
}

int modInv(int a, int m) {
    a %= m;
    for (int x = 1; x < m; x++) if ((a * x) % m == 1) return x;
    return -1;
}

// Calculate determinant of 3x3 matrix mod 26
int det3x3(int M[S][S]) {
    int det = M[0][0]*(M[1][1]*M[2][2] - M[1][2]*M[2][1])
            - M[0][1]*(M[1][0]*M[2][2] - M[1][2]*M[2][0])
            + M[0][2]*(M[1][0]*M[2][1] - M[1][1]*M[2][0]);
    return mod26(det);
}

// Function to get cofactor matrix element
int cofactor(int M[S][S], int p, int q) {
    int temp[2][2], r = 0, c = 0;
    for (int i = 0; i < S; i++) {
        for (int j = 0; j < S; j++) {
            if (i != p && j != q) {
                temp[r][c++] = M[i][j];
                if (c == 2) { c = 0; r++; }
            }
        }
    }
    return temp[0][0]*temp[1][1] - temp[0][1]*temp[1][0];
}

// Find adjoint matrix mod 26
void adjoint(int M[S][S], int adj[S][S]) {
    for (int i = 0; i < S; i++) {
        for (int j = 0; j < S; j++) {
            int sign = ((i+j) % 2 == 0) ? 1 : -1;
            adj[j][i] = mod26(sign * cofactor(M, i, j)); // transpose while assigning
        }
    }
}

// Find inverse matrix mod 26
int inverseMatrix(int M[S][S], int inv[S][S]) {
    int det = det3x3(M);
    int detInv = modInv(det, 26);
    if (detInv == -1) return 0; // No inverse

    int adj[S][S];
    adjoint(M, adj);

    for (int i = 0; i < S; i++) {
        for (int j = 0; j < S; j++) {
            inv[i][j] = mod26(adj[i][j] * detInv);
        }
    }
    return 1;
}

// Multiply matrix M(SxS) by vector in[Sx1]
void multiply(int M[S][S], int in[S], int out[S]) {
    for (int i = 0; i < S; i++) {
        int sum = 0;
        for (int j = 0; j < S; j++) {
            sum += M[i][j] * in[j];
        }
        out[i] = mod26(sum);
    }
}

void hillCipher(char *text, char *key, char *out, int len, int enc) {
    int K[S][S], KM[S][S];
    // Build key matrix from key string (assumed length 9)
    for (int i = 0; i < S * S; i++) {
        K[i / S][i % S] = (key[i] - 'A') % 26;
    }

    if (!enc) {
        if (!inverseMatrix(K, KM)) {
            printf("Key matrix not invertible. Exiting.\n");
            exit(1);
        }
    } else {
        memcpy(KM, K, sizeof(K));
    }

    for (int i = 0; i < len; i += S) {
        int vec_in[S], vec_out[S];
        for (int j = 0; j < S; j++) {
            vec_in[j] = (i + j < len) ? (text[i + j] - 'A') : 'X' - 'A'; // pad with 'X' if needed
        }
        multiply(KM, vec_in, vec_out);
        for (int j = 0; j < S; j++) {
            out[i + j] = vec_out[j] + 'A';
        }
    }
    out[len] = '\0';
}

int main() {
    char plaintext[100], key[100], ciphertext[100], decrypted[100];
    printf("Enter key (9 letters): ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = 0;
    if (strlen(key) != 9) {
        printf("Key must be exactly 9 letters.\n");
        return 1;
    }
    for (int i = 0; i < 9; i++) key[i] = toupper(key[i]);

    printf("Enter plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = 0;
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) plaintext[i] = toupper(plaintext[i]);

    // Pad plaintext to multiple of 3
    while (len % S != 0) {
        plaintext[len++] = 'X';
    }
    plaintext[len] = '\0';

    hillCipher(plaintext, key, ciphertext, len, 1);
    printf("Encrypted: %s\n", ciphertext);

    hillCipher(ciphertext, key, decrypted, len, 0);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}
```


## OUTPUT:

![CRYPTO EX 3](https://github.com/user-attachments/assets/22aa6f7b-6e47-4020-b330-6855fbcb103f)



## RESULT:
The Hill cipher successfully encrypted the given plaintext by converting it into matrix form and multiplying with the key matrix. For example, using the key "GYBNQKURP" and plaintext "ACT," the ciphertext obtained was "POH." Upon decryption, the original plaintext "ACT" was correctly recovered, demonstrating the effectiveness of the Hill cipher in both encryption and decryption processes.

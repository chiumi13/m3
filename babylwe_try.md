## LWE密碼學應用
A是一個m x n矩陣，s是一個n維向量，e是一個m維向量。
定義LWE(s,e) : b = As + e。
由此可以構造一個對稱加密算法。
加密算法定義如下:
s作為密鑰k使用；
(A,e)這一組數據在加密時隨機生成；
由s, A, e所求得的值b作為一次性密碼本的密鑰使用，同密文m進行異或操作。
這一算法和傳統對稱密鑰加密算法的區別的關鍵在於，加密方不將誤差數據e傳送給解密方，導致解密方所解得明文存在一個小的誤差。



```# Import necessary libraries
import os
from hashlib import sha256
from Crypto.Cipher import AES
from sage.all import *

def solve_lwe_and_decrypt(A_list, b_list, ct_bytes):
    """
    Uses the LLL algorithm to solve the LWE problem and decrypt the flag.

    Args:
        A_list (list): List form of matrix A.
        b_list (list): List form of vector b.
        ct_bytes (bytes): Encrypted ciphertext.
    
    Returns:
        bytes: Decrypted flag.
    """
    # Parameter settings
    n = 64
    m = 200
    p = 1048583
    F = GF(p)
    
    try:
        # Reconstruct SageMath's matrix and vector from file data
        print("正在從檔案數據重建 A 矩陣和 b 向量...")
        # Correctly define the dimensions of matrix A as m x n
        A = matrix(F, m, n, A_list) 
        b = vector(F, b_list)

        # Construct the lattice basis for LWE-SVP conversion
        print("正在構造用於 LLL 演算法的格基...")
        L = matrix(ZZ, n + m)
        
        # Construct the row vectors of the LWE lattice basis
        # The first n rows correspond to the secret vector components
        for i in range(n): 
            L[i, i] = 1 
            # Place the elements of A^T in the lattice
            for j in range(m): 
                L[i, n + j] = int(A[j, i]) 
        
        # The next m rows correspond to the error vector components
        for i in range(m): 
            L[n + i, n + i] = p 

        # Execute the LLL algorithm to find a reduced basis
        print("正在執行 LLL 演算法...")
        L_lll = L.LLL()

        # The first vector in the reduced basis (L_lll[0]) is usually the shortest vector we're looking for
        # The first n components of this short vector are the secret vector s
        s_candidate = L_lll[0][:n]
        
        # Verify the candidate s
        s_int_list = [int(x) for x in s_candidate]
        s_test = vector(F, s_int_list)
        
        # Check if the result of b - A*s is sufficiently small
        # Fix: The operation should be A * s_test, not A.transpose() * s_test
        print("正在驗證找到的祕密向量...")
        e_test = b - A * s_test
        
        # The max norm of the error vector should be small (less than p/2)
        if max(e_test.apply_map(lambda x: abs(x.lift()))) < p / 2:
            s_final = s_test
        else:
            s_final = -s_test
        
        # Derive the AES key and Nonce from the secret vector s to decrypt the flag
        print("正在使用祕密向量解密 flag...")
        key = sha256(str(s_final.change_ring(ZZ)).encode()).digest()[:24]
        aes = AES.new(key[:16], AES.MODE_CTR, nonce=key[-8:])
        flag = aes.decrypt(ct_bytes)
        
        return flag
    
    except Exception as e:
        print(f"解密過程中發生錯誤: {e}")
        return None

# The original string representation of the file content
file_content = """A = [...]
b = [...]
ct = ...
"""

# Convert string to usable Python objects
lines = file_content.strip().split('\n')
A_str = lines[0].split(' = ')[1]
b_str = lines[1].split(' = ')[1]

# Manually handle the ct string
ct_str_raw = lines[2].split(' = ')[1][2:-1]  
ct_bytes = bytes(ct_str_raw, 'latin-1').decode('unicode_escape').encode('latin-1')

A_list = eval(A_str)
b_list = eval(b_str)

# Execute decryption
flag = solve_lwe_and_decrypt(A_list, b_list, ct_bytes)

if flag:
    print(f"\n成功解密！Flag 是: {flag.decode()}")
else:
    print("\n解密失敗。請檢查輸入資料或程式碼。")
```
  
  
  
### 跑出來是flag.decode()  
---  
- 修改 flag.decode()  
-- flag.decode('latin1')   
-- flag.decode('hex')  
- 最後解出來是  
    0O·oioi6o!￡t 7U§Myio:G?m?c?T@ioYC )jDU?iCC?E??c
  
#### LWE 演算法參考
https://www.maths.ox.ac.uk/system/files/attachments/lattice-reduction-and-attacks.pdf  

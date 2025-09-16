# 1. 引入套件
```
from sage.all import *
from hashlib import sha256
from Crypto.Cipher import AES
from lll_cvp import reduce_mod_p
from output import A, b, ct
```


sage.all：使用 SageMath 的數學工具（矩陣、有限域、格基底化簡等）。
hashlib.sha256：生成 SHA-256 雜湊。
Crypto.Cipher.AES：AES 加密/解密。
lll_cvp.reduce_mod_p：自定義的格子化簡工具。
output：載入公開參數 A（矩陣）、b（向量）、ct（密文）。

# 2. 設定參數
```
n = 64      # 秘密向量 s 的維度
m = 200     # 方程數量
p = 1048583 # 模數 (一個質數)
F = GF(p)   # 定義有限域 GF(p)
```


這裡的 n, m, p 是 LWE 問題的參數，s 與 e（誤差向量）都在模 p 下運算。
# 3. LWE 結構

程式的註解說明了基本想法：
> lwe 有 b = A*s + e
> 存在某些 u,v 使得 e' = u*e + v*one 是小向量 (one 是全 1 向量)
> 於是 u*b + v*one = u*A*s + e'
> 所以 e' 是在 span(col(A), b, one) 裡的一個短向量


在 LWE 裡我們知道 b = A*s + e，但 e 是小誤差向量。
如果能找到某個線性組合，把 e 轉換成一個「更好辨識」的小向量 e'，就能透過格基底化簡找出來。最後反推出誤差 e，進而解出秘密 s。

# 4. 構造格子
```
A = matrix(F, m, n, A)
b = vector(F, b)
one = vector(F, [1] * m)
L = A.T.stack(b).stack(one)
```


這裡把矩陣和向量堆疊起來：
A.T 是轉置的 A。
stack(b)、stack(one) 把 b 和 全 1 向量 放到一起。
最後形成一個格子基底 L，裡面包含了 (col(A), b, one) 的張成空間。

# 5. 格基底化簡
```
rr = reduce_mod_p(L, p)
rr = rr.BKZ(block_size=4, fp="ld")
rr = rr.BKZ(block_size=20)
print(rr[1])  # vector e', small
```


先用 reduce_mod_p 把基底取模。
接著跑 BKZ（格基底化簡算法，比 LLL 更強），逐步縮小格基底。
得到 rr[1]，這是一個「短向量」，應該就是構造出來的 e'。

# 6. 驗證與求解
```
assert len(set(rr[1])) == 3, "failed QQ"
*_, u, v = L.solve_left(rr[1])
e = (rr[1] - v * one) / u
print(e)  # vector e
s = A.solve_right(b - e)
```


驗證 rr[1] 的值型態（它應該只會有三種不同的元素）。
解線性方程，找出對應的 u, v。
由公式反推出原本的誤差向量 e。
最後用 s = A.solve_right(b - e) 得到秘密向量 s。

# 7. 解密
```
key = sha256(str(s).encode()).digest()[:24]
aes = AES.new(key[:16], AES.MODE_CTR, nonce=key[-8:])
flag = aes.decrypt(ct)
print(flag)
```


將秘密向量 s 的字串算 SHA-256，截取前 24 bytes。
前 16 bytes 當作 AES 密鑰，後 8 bytes 當作 CTR 模式的 nonce。
用 AES 解出密文 ct，得到明文 flag。
這支程式透過構造格子、用 BKZ 找到一個短向量，進而還原 LWE 的誤差 e，再算出秘密 s，最後用 s 生成 AES key，解密拿到 flag。




# 流程圖（簡易示意）
  [公開] A, b, one         (LWE: b = A*s + e)  
         │  
         ▼  
  ┌───────────────────────────────┐   
  │ 建構矩陣 L = [ A^T ; b ; one ] │   
  └───────────────────────────────┘   
         │  
         ▼  
  ┌───────────────────────────────┐           
 │ 對 L 做格基底化簡 (reduce_mod_p + BKZ) │   
  └───────────────────────────────┘           
         │  
         ▼  
  ┌───────────────────────────────┐      
  │ 取得短向量 rr[1] ≈ e' = u*e+v*one │   
  └───────────────────────────────┘      
         │
         ▼
  ┌────────────────────────────────────────────┐                
  │ 用 L.solve_left(rr[1]) 解出 u, v，反推 e = (e' - v*one)/u │  
  └────────────────────────────────────────────┘                
         │  
         ▼  
  ┌───────────────────────────────┐             
  │ 計算秘密向量 s = A.solve_right(b - e) │      
  └───────────────────────────────┘             
         │  
         ▼  
  ┌────────────────────────────────────────┐     
  │ key = SHA256(str(s)).digest()[:24]     │     
  │ (前16 bytes → AES key, 後8 bytes → nonce) │  
  └────────────────────────────────────────┘     
         │  
         ▼  
  ┌───────────────────────────────┐      
  │ 用 AES-CTR(key, nonce) 解密 ct │    
  └───────────────────────────────┘      
         │  
         ▼  
      [明文] flag  

#

左上角標註 A, b, one 為已知的公開資料（one 為全 1 向量）。
透過把這些向量放進格子基底並用 BKZ 找短向量，可以找到形如 e' = u*e + v*one 的短向量。
解出 u, v 後可還原真正的誤差 e，再從 b - e 求得秘密 s。
s 經 SHA-256 決定 AES 金鑰與 nonce，最後解密出 flag。

# 作者blog writeup 
  - https://blog.maple3142.net/2023/11/05/tsg-ctf-2023-writeups/

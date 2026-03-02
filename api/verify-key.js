// 导入 Node.js 内建的加密模块
const crypto = require('crypto');

// 定义一个函数来验证密钥
function verifyKey(receivedHash, providedSalt, expectedIterations) {
  // 你的“正确”密码或种子。这里只是一个例子，你需要修改它。
  // 例如，你可以设定一个固定密码 "MySecretPassword123"
  const correctSeed = "MySecretPassword123";

  // 使用相同的盐和迭代次数对“正确”密码进行哈希
  const correctHash = crypto.pbkdf2Sync(
    correctSeed,
    providedSalt,
    expectedIterations,
    32, // 输出密钥长度，32字节
    'sha256' // 哈希算法
  ).toString('hex');

  // 比较计算出的哈希值和从前端收到的哈希值
  return crypto.timingSafeEqual(
    Buffer.from(correctHash),
    Buffer.from(receivedHash)
  );
}

// Vercel 要求的导出函数，用于处理 HTTP 请求
module.exports = async function handler(req, res) {
  // 只接受 POST 请求
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    // 从前端请求体中获取数据
    const { hash, salt, iterations } = req.body;

    // 简单验证参数是否存在
    if (!hash || !salt || !iterations) {
      return res.status(400).json({ error: 'Missing required parameters: hash, salt, iterations' });
    }

    // 调用验证函数
    const isValid = verifyKey(hash, salt, parseInt(iterations));

    if (isValid) {
      // 如果验证成功，返回激活成功的响应
      res.status(200).json({ activated: true, message: "Activation successful!" });
    } else {
      // 如果验证失败，返回错误
      res.status(401).json({ activated: false, error: "Invalid key" });
    }
  } catch (error) {
    console.error("Verification Error:", error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
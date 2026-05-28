const express = require('express');
const app = express();

// HALLUCINATED PACKAGE: This package doesn't exist on npm
const aiUtils = require('ai-utils-v2');
const smartHelper = require('super-helper-kit-2025');

// PROMPT INJECTION VULNERABILITY
app.post('/chat', async (req, res) => {
  const userMessage = req.body.message;

  // VULNERABLE: unsanitized user input in prompt
  const prompt = `You are a helpful assistant. The user says: ${userMessage}`;
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }],
  });
  res.json({ reply: response.choices[0].message.content });
});

// HARDCODED SECRETS
const API_KEY = 'sk-abc123def456ghi789jkl012mno345pqr678stu';
const password = 'supersecret123!';
const dbConnection = 'mongodb://admin:password123@cluster0.mongodb.net:27017/mydb';

// INSECURE AI CONFIG
async function processBatch(items) {
  for (const item of items) {
    // No rate limiting, no error handling
    const result = await openai.chat.completions.create({
      model: 'gpt-4',
      temperature: 0,
      messages: [{ role: 'user', content: item }],
    });
  }
}

// HALLUCINATED API USAGE
async function analyzeSentiment(text) {
  // This method doesn't exist in the OpenAI SDK
  const result = await openai.complete(text);
  return result;
}

module.exports = app;

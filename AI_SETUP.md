# 🤖 AI Natural Language Expense Entry

## Quick Setup

### 1. Get OpenAI API Key
1. Go to https://platform.openai.com/api-keys
2. Create a new API key
3. Copy the key (starts with `sk-...`)

### 2. Set Environment Variable
**On Render.com (Production):**
- Go to your service dashboard
- Add environment variable: `OPENAI_API_KEY` = `your-key-here`

**Local Development:**
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

### 3. Test the Feature
1. Go to your dashboard
2. You'll see the "✨ Quick Add with AI" section
3. Try these examples:
   - `Pizza with roommates $45, I paid, split equally`
   - `Uber $15, paid by Sarah`
   - `Groceries $120, split with John and Mike`
   - `Coffee $8, I owe Lisa`

## How It Works
1. **Type naturally** - describe your expense in plain English
2. **AI parses** - GPT-3.5-turbo extracts amount, category, who paid, splits
3. **Preview** - confirm the parsed details
4. **Create** - expense is added with proper splits

## Features
- ✅ Automatic amount extraction
- ✅ Smart category detection
- ✅ Member name recognition
- ✅ Split calculation
- ✅ Paid-by detection
- ✅ Error handling & fallbacks

## Cost
- ~$0.001-0.002 per expense parsing
- Very affordable for personal use

## Fallback
If AI fails or key is missing, the manual "📝 Manual" button works as before. 
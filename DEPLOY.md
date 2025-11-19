# Deployment Guide for Render.com

This guide will help you deploy the realtime-chat WebSocket server to Render.com.

## Prerequisites

1. A GitHub account with your code pushed to a repository
2. A Render.com account (free tier available)

## Deployment Steps

### 1. Prepare Your Repository

Make sure your code is pushed to GitHub with the following files:
- `server_websocket.py` (main server file)
- `requirements.txt` (Python dependencies)
- `render.yaml` (Render configuration - optional but recommended)

### 2. Deploy on Render.com

#### Option A: Using render.yaml (Recommended)

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click **"New +"** → **"Blueprint"**
3. Connect your GitHub repository
4. Render will automatically detect `render.yaml` and configure the service

#### Option B: Manual Setup

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure the service:
   - **Name**: `realtime-chat-websocket` (or your preferred name)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python server_websocket.py`
   - **Plan**: Free (or choose a paid plan)

### 3. Configure Environment Variables

In the Render dashboard, go to your service → **Environment** tab and add:

#### Required Variables:
- `SERVER_HOST`: `0.0.0.0` (required for Render)
- `API_JWT_SECRET`: Generate a strong random secret (e.g., use `openssl rand -hex 32`)
- `SIGNING_SECRET`: Generate another strong random secret

#### Optional Variables:
- `SERVER_PORT`: Leave empty (Render provides `PORT` automatically)
- `PDF_FILE_ID`: Google Drive file ID if using Google Drive for PDFs
- `PDF_LOCAL_PATH`: Path to local PDF file (if not using Google Drive)
- `PDF_UPLOAD_DIR`: `./pdf_uploads` (directory for signed PDFs)
- `JWT_EXP`: `3600` (JWT expiration in seconds)
- `SIGNATURE_TOKEN_EXPIRY`: `1800` (signature token expiration in seconds)

### 4. Important Notes

#### WebSocket Support
Render.com supports WebSocket connections, but you need to:
- Use **wss://** (secure WebSocket) in production
- Your service URL will be: `wss://your-service-name.onrender.com`

#### Port Configuration
- Render automatically provides a `PORT` environment variable
- The server is configured to use `PORT` if available, falling back to `SERVER_PORT`
- **Do not** set `SERVER_PORT` in Render - let it use the provided `PORT`

#### Persistent Storage
- The free tier on Render has **ephemeral storage** (data is lost on restart)
- Signed PDFs and RSA keys will be regenerated on each deployment
- For production, consider:
  - Using a database (PostgreSQL on Render) for persistent data
  - Using Render's disk storage (paid plans)
  - External storage (S3, Google Cloud Storage, etc.)

#### Health Checks
- Render will check if your service is running
- The WebSocket server doesn't have an HTTP endpoint by default
- Consider adding a simple HTTP health check endpoint if needed

### 5. Testing Your Deployment

1. Wait for the deployment to complete (usually 2-5 minutes)
2. Check the logs in Render dashboard for any errors
3. Test the WebSocket connection:
   ```javascript
   const client = new ChatClient("wss://your-service-name.onrender.com");
   await client.connect();
   await client.login("admin", "admin123");
   ```

### 6. Updating Your Deployment

- Push changes to your GitHub repository
- Render will automatically detect and deploy the changes
- Or manually trigger a deploy from the Render dashboard

## Troubleshooting

### Connection Issues
- Ensure you're using `wss://` (not `ws://`) for secure connections
- Check that the service is running (not sleeping on free tier)
- Verify environment variables are set correctly

### Service Sleeping (Free Tier)
- Free tier services sleep after 15 minutes of inactivity
- First request after sleep may take 30-60 seconds to wake up
- Consider upgrading to a paid plan for always-on service

### Port Already in Use
- This shouldn't happen on Render, but if it does, check logs
- Ensure you're not setting `SERVER_PORT` manually

### Missing Dependencies
- Check `requirements.txt` includes all dependencies
- Review build logs in Render dashboard

## Security Recommendations

1. **Change Default Secrets**: Never use default JWT secrets in production
2. **Use Strong Passwords**: Update user passwords in `server_websocket.py`
3. **Enable HTTPS/WSS**: Always use secure WebSocket connections
4. **Environment Variables**: Store all secrets in Render's environment variables
5. **Database**: Consider moving user database to a secure database service

## Support

For Render-specific issues, check:
- [Render Documentation](https://render.com/docs)
- [Render Community](https://community.render.com)

For application issues, check the application logs in the Render dashboard.


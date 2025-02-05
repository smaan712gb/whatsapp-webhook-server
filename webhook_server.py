import logging
from fastapi import FastAPI, Request, Response
import os
from dotenv import load_dotenv
import hmac
import hashlib
import json
import aiohttp

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI()

async def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify that the webhook request came from Facebook"""
    app_secret = os.getenv('WHATSAPP_APP_SECRET')
    if not app_secret:
        return False
        
    expected_signature = hmac.new(
        app_secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, f"sha256={expected_signature}")

async def send_whatsapp_message(to: str, message: str):
    """Send a WhatsApp message"""
    token = os.getenv('WHATSAPP_ACCESS_TOKEN')
    phone_number_id = os.getenv('WHATSAPP_PHONE_NUMBER_ID')
    
    url = f"https://graph.facebook.com/v17.0/{phone_number_id}/messages"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    data = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": message}
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=data) as response:
            return await response.json()

@app.get("/webhook")
async def verify_webhook(request: Request):
    """Handle webhook verification from WhatsApp"""
    try:
        mode = request.query_params.get('hub.mode')
        token = request.query_params.get('hub.verify_token')
        challenge = request.query_params.get('hub.challenge')
        
        verify_token = os.getenv('WHATSAPP_VERIFY_TOKEN')
        
        if mode and token:
            if mode == 'subscribe' and token == verify_token:
                logger.info("Webhook verified successfully")
                return Response(content=challenge)
            else:
                logger.error("Webhook verification failed")
                return Response(status_code=403)
                
    except Exception as e:
        logger.error(f"Error handling verification: {e}")
        return Response(status_code=500)

@app.post("/webhook")
async def webhook_handler(request: Request):
    """Handle incoming webhook updates"""
    try:
        # Verify signature
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature:
            return Response(status_code=403, content="No signature")
            
        body = await request.body()
        if not await verify_signature(body, signature):
            return Response(status_code=403, content="Invalid signature")
            
        # Process the update
        update = json.loads(body)
        
        # Handle different types of updates
        entry = update.get('entry', [{}])[0]
        changes = entry.get('changes', [{}])[0]
        
        if changes.get('field') == 'messages':
            value = changes.get('value', {})
            messages = value.get('messages', [])
            
            for message in messages:
                await process_message(message)
                
        return Response(status_code=200)
        
    except Exception as e:
        logger.error(f"Error handling update: {e}")
        return Response(status_code=500)

async def process_message(message: dict):
    """Process an incoming message"""
    try:
        message_type = message.get('type')
        if message_type == 'text':
            text = message.get('text', {}).get('body', '')
            from_number = message.get('from')
            
            # Handle commands
            if text.lower() == 'status':
                await send_whatsapp_message(
                    from_number,
                    "WhatsApp webhook is running. Use 'help' to see available commands."
                )
            elif text.lower() == 'help':
                help_text = (
                    "Available Commands:\n"
                    "• status - Check webhook status\n"
                    "• help - Show this help message"
                )
                await send_whatsapp_message(from_number, help_text)
                
    except Exception as e:
        logger.error(f"Error processing message: {e}")

# Create app instance for gunicorn
app = app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv('PORT', '10000'))
    host = '0.0.0.0'
    uvicorn.run(app, host=host, port=port)

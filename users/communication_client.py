import requests
import json
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_templated_email(recipient: str, template_id: str, context: dict):
    """
    Calls the email-service to send a templated email.

    Args:
        recipient (str): The email address of the recipient.
        template_id (str): The unique ID of the email template to use.
        context (dict): A dictionary with the dynamic data for the template.

    Returns:
        bool: True if the email was successfully queued, False otherwise.
    """
    email_service_url = settings.EMAIL_SERVICE_URL
    internal_service_token = settings.INTERNAL_SERVICE_TOKEN

    if not email_service_url or not internal_service_token:
        logger.error("EMAIL_SERVICE_URL or INTERNAL_SERVICE_TOKEN is not configured.")
        return False

    mutation = """
        mutation SendTemplatedEmail($recipient: String!, $templateId: String!, $contextJson: String!) {
            sendTemplatedEmail(recipient: $recipient, templateId: $templateId, contextJson: $contextJson) {
                success
                message
            }
        }
    """

    variables = {
        'recipient': recipient,
        'templateId': template_id,
        'contextJson': json.dumps(context)
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {internal_service_token}'
    }

    try:
        response = requests.post(
            email_service_url,
            json={'query': mutation, 'variables': variables},
            headers=headers,
            timeout=10 # 10-second timeout
        )
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        response_data = response.json()
        if 'errors' in response_data:
            logger.error(f"Error from email service: {response_data['errors']}")
            return False

        success = response_data.get('data', {}).get('sendTemplatedEmail', {}).get('success', False)
        if not success:
            message = response_data.get('data', {}).get('sendTemplatedEmail', {}).get('message', 'No message provided.')
            logger.error(f"Failed to queue email in email-service. Reason: {message}")
            return False
            
        logger.info(f"Successfully queued '{template_id}' email for {recipient} via email-service.")
        return True

    except requests.exceptions.RequestException as e:
        logger.error(f"Could not connect to email service at {email_service_url}. Error: {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while calling the email service: {e}")
        return False 